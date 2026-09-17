#!/usr/bin/env python3
"""Run the test cases in `tests/` against the rules in `rules/`.

## Why this exists

`CONTRIBUTING.md` says *"Rules without tests aren't merged."* The repo has fifty test files,
each one specifying event sets and whether the rule should fire — and until this existed,
**nothing ran any of them.** The promise was made to strangers on a public repo and could not
be kept, because there was no way to check a contributor's tests or our own.

That is the same failure the product itself is built to refuse: a check that looks like it is
happening and is not. `rule_lint.py` catches structural holes — a condition naming a selection
that does not exist, a correlation pointing at nothing. It cannot tell you whether a rule
actually FIRES on the events it is supposed to fire on, which is the only question that
matters once the YAML parses.

## What it evaluates

Everything the corpus actually uses, and nothing it does not:

    modifiers      |contains  |endswith  |contains|all   (plain equality otherwise)
    values         a scalar, or a list meaning ANY of these
    conditions     and / or / not / parentheses, bare selection names, and `1 of prefix_*`
    correlation    event_count  — N matching events per group inside the window
                   value_count  — N DISTINCT values of a field per group inside the window

## The condition parser does NOT use eval, deliberately

This repo takes pull requests. A `condition:` string arrives from a stranger, and
`eval(condition, ...)` on a contributed file is remote code execution wearing a detection
rule. It is a recursive-descent parser instead — about forty lines, and it removes the
question rather than mitigating it.

    python tools/rule_test.py            # run everything
    python tools/rule_test.py A-001      # one rule, by id prefix
    python tools/rule_test.py --list     # rules with no test file

Exits non-zero on any failure, so it works as a CI gate.
"""
import argparse
import fnmatch
import pathlib
import re
import sys

import yaml

BASE = pathlib.Path(__file__).resolve().parent.parent
RULES = BASE / "rules"
TESTS = BASE / "tests"


# ── matching one event ────────────────────────────────────────────────────────

def _as_list(v):
    return v if isinstance(v, list) else [v]


def _field_matches(event_value, expected, mods) -> bool:
    """One field of one selection against one event.

    A missing field never matches. That is deliberate and it is the direction that keeps a
    rule honest: an event without the field cannot be evidence FOR the rule, and treating
    absent-as-match is how a selection quietly becomes "everything".
    """
    if event_value is None:
        return False
    ev = str(event_value)
    wanted = [str(x) for x in _as_list(expected)]

    if "contains" in mods and "all" in mods:
        return all(w.lower() in ev.lower() for w in wanted)
    if "contains" in mods:
        return any(w.lower() in ev.lower() for w in wanted)
    if "endswith" in mods:
        return any(ev.lower().endswith(w.lower()) for w in wanted)
    if "startswith" in mods:
        return any(ev.lower().startswith(w.lower()) for w in wanted)
    # Plain equality, case-insensitive: Windows event fields are not case-stable.
    return any(ev.lower() == w.lower() for w in wanted)


def selection_matches(event: dict, selection) -> bool:
    """Every field in the selection must match (AND); a list of values is ANY (OR)."""
    if isinstance(selection, list):
        # A list of maps at selection level means ANY of them.
        return any(selection_matches(event, s) for s in selection)
    for key, expected in selection.items():
        parts = str(key).split("|")
        field, mods = parts[0], [m.lower() for m in parts[1:]]
        if not _field_matches(event.get(field), expected, mods):
            return False
    return True


# ── the condition expression ──────────────────────────────────────────────────

class _Cond:
    """Recursive descent over `and` / `or` / `not` / parens / names / `1 of pat*`.

    No eval. See the module docstring: contributed rules must never be executed as code.
    """

    def __init__(self, text: str, names: dict):
        self.toks = re.findall(r"\(|\)|\b1 of\b|\band\b|\bor\b|\bnot\b|[A-Za-z_][\w*]*", text)
        self.i = 0
        self.names = names

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self):
        t = self.peek()
        self.i += 1
        return t

    def parse(self) -> bool:
        v = self._or()
        if self.peek() is not None:
            raise ValueError(f"trailing tokens in condition: {self.toks[self.i:]}")
        return v

    def _or(self) -> bool:
        v = self._and()
        while self.peek() == "or":
            self.take()
            v = self._and() or v
        return v

    def _and(self) -> bool:
        v = self._not()
        while self.peek() == "and":
            self.take()
            v = self._not() and v
        return v

    def _not(self) -> bool:
        if self.peek() == "not":
            self.take()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        t = self.take()
        if t == "(":
            v = self._or()
            if self.take() != ")":
                raise ValueError("unbalanced parentheses in condition")
            return v
        if t == "1 of":
            pat = self.take()
            hits = [v for k, v in self.names.items() if fnmatch.fnmatch(k, pat)]
            if not hits:
                raise ValueError(f"`1 of {pat}` matches no selection")
            return any(hits)
        if t is None:
            raise ValueError("condition ended unexpectedly")
        if t not in self.names:
            raise ValueError(f"condition names `{t}`, which is not a selection")
        return self.names[t]


def event_matches_rule(event: dict, detection: dict) -> bool:
    names = {k: selection_matches(event, v)
             for k, v in detection.items() if k != "condition"}
    return _Cond(str(detection["condition"]), names).parse()


# ── correlation ───────────────────────────────────────────────────────────────

_SPAN = re.compile(r"^(\d+)\s*([smhd])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def timespan_seconds(v) -> int:
    m = _SPAN.match(str(v).strip())
    if not m:
        raise ValueError(f"unparseable timespan: {v!r}")
    return int(m.group(1)) * _UNIT[m.group(2)]


def _group_key(event: dict, fields):
    return tuple(str(event.get(f, "")) for f in (fields or []))


def correlation_fires(matched: list, corr: dict) -> bool:
    """Does any sliding window satisfy the correlation?

    The window is anchored on each event in turn rather than on fixed buckets. Fixed buckets
    are the classic way a threshold rule silently under-fires: ten failures spanning a bucket
    boundary become six and four, and nothing triggers.
    """
    span = timespan_seconds(corr.get("timespan", "5m"))
    cond = corr.get("condition") or {}
    gte = cond.get("gte")
    if gte is None:
        raise ValueError("correlation condition has no `gte`")
    ctype = corr.get("type")
    groups = {}
    for e in matched:
        groups.setdefault(_group_key(e, corr.get("group-by")), []).append(e)

    for events in groups.values():
        events.sort(key=lambda e: e.get("t", 0))
        for i, start in enumerate(events):
            window = [e for e in events[i:]
                      if e.get("t", 0) - start.get("t", 0) <= span]
            if ctype == "event_count":
                if len(window) >= gte:
                    return True
            elif ctype == "value_count":
                field = cond.get("field")
                if field is None:
                    raise ValueError("value_count correlation has no `field`")
                if len({str(e.get(field)) for e in window
                        if e.get(field) is not None}) >= gte:
                    return True
            else:
                raise ValueError(f"unsupported correlation type: {ctype!r}")
    return False


# ── running a rule against its cases ──────────────────────────────────────────

def load_rule(path: pathlib.Path):
    docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    base = next((d for d in docs if "detection" in d), None)
    corr = next((d for d in docs if "correlation" in d), None)
    if base is None:
        raise ValueError(f"{path.name}: no document with a `detection` block")
    return base, corr


def expand_case(case: dict) -> list:
    """The events for one case, from either fixture shape.

    `events:` is an explicit list. `events_generator:` is a template repeated `count` times
    and spread evenly across `window_seconds`, with `{{i}}` replaced by the index — which is
    how a case asserting "500 mailbox accesses in an hour" is written without five hundred
    lines of YAML. Nineteen cases use it, and a runner that only understood the explicit form
    would report every one of them as a rule that failed to fire.

    The events are spread so the FIRST is at t=0 and the LAST is exactly at `window_seconds`.
    Bunching them at the start would let a case pass against a rule whose window is far too
    short, which is the opposite of what these high-volume cases exist to prove.
    """
    if "events" in case:
        return case["events"] or []

    gen = case.get("events_generator") or {}
    count = int(gen.get("count") or 0)
    window = float(gen.get("window_seconds") or 0)
    template = gen.get("template") or {}
    step = window / (count - 1) if count > 1 else 0.0

    out = []
    for i in range(count):
        e = {}
        for k, v in template.items():
            e[k] = (v.replace("{{i}}", str(i)) if isinstance(v, str) else v)
        e.setdefault("t", round(i * step))
        out.append(e)
    return out


def rule_fires(base: dict, corr: dict, events: list) -> bool:
    matched = [e for e in events if event_matches_rule(e, base["detection"])]
    if corr is None:
        return bool(matched)
    return correlation_fires(matched, corr["correlation"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("filter", nargs="?", default="",
                    help="only rules whose filename starts with this (e.g. A-001)")
    ap.add_argument("--list", action="store_true",
                    help="list rules that have no test file, and stop")
    args = ap.parse_args()

    rules = {p.stem: p for p in sorted(RULES.rglob("*.yml"))}
    tests = {p.name.split(".test")[0]: p for p in sorted(TESTS.glob("*.test.yml"))}

    if args.list:
        untested = sorted(set(rules) - set(tests))
        orphan = sorted(set(tests) - set(rules))
        for r in untested:
            print(f"  NO TEST   {r}")
        for t in orphan:
            print(f"  NO RULE   {t}  (test file names a rule that does not exist)")
        print(f"\n{len(rules)} rule(s), {len(tests)} with tests, {len(untested)} without.")
        return 1 if untested or orphan else 0

    ran = passed = failed = 0
    errors = []
    for stem, tpath in tests.items():
        if args.filter and not stem.startswith(args.filter):
            continue
        rpath = rules.get(stem)
        if rpath is None:
            errors.append(f"{tpath.name}: names rule `{stem}`, which does not exist")
            continue
        try:
            base, corr = load_rule(rpath)
            spec = yaml.safe_load(tpath.read_text(encoding="utf-8")) or {}
        except Exception as exc:                                # noqa: BLE001
            errors.append(f"{tpath.name}: could not load - {exc}")
            continue

        for case in spec.get("cases") or []:
            ran += 1
            if "events" not in case and "events_generator" not in case:
                failed += 1
                errors.append(f"{stem}: {case.get('name','?')} - case has neither "
                              f"`events` nor `events_generator`")
                continue
            want = bool(case.get("should_fire"))
            try:
                got = rule_fires(base, corr, expand_case(case))
            except Exception as exc:                            # noqa: BLE001
                failed += 1
                errors.append(f"{stem}: {case.get('name','?')} - ERROR {exc}")
                continue
            if got == want:
                passed += 1
            else:
                failed += 1
                errors.append(
                    f"{stem}: {case.get('name','?')}\n"
                    f"      expected {'FIRE' if want else 'no fire'}, "
                    f"got {'FIRE' if got else 'no fire'}")

    print(f"ran {ran} case(s) across {len(tests)} rule file(s)")
    if errors:
        print("\nFAILURES")
        for e in errors:
            print(f"  {e}")
        print(f"\n{failed} failed, {passed} passed.")
        return 1
    print(f"ALL PASS - {passed} case(s)")

    untested = sorted(set(rules) - set(tests))
    if untested and not args.filter:
        # Reported, never silent. A rule with no test is not a passing rule, and a green
        # run that hides eight of them is the thing this tool was written to stop.
        print(f"\n{len(untested)} rule(s) have NO TEST and were not checked:")
        for r in untested:
            print(f"  {r}")
        print("`rule_test.py --list` exits non-zero on these.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
