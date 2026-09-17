#!/usr/bin/env python3
"""Structural linter for Chronolith detection rules.

Catches the "glaring hole" class cheaply, before a rule is ever loaded by an
engine: duplicate YAML keys, conditions referencing selections that do not
exist, correlation rules pointing at a base rule name nothing defines, logsource
and EventID that cannot route to each other, missing required fields, bad level.

These are the failures that look fine in review and simply never fire in
production, which is the worst outcome for a detection rule: the estate believes
it is covered.

Run from anywhere:

    python tools/rule_lint.py

Exits non-zero when anything is flagged, so it works as a CI gate and a
pre-commit check.
"""
import glob
import re
import sys
from pathlib import Path

import yaml

# Resolve the repo from this file's own location. Previously a hardcoded
# absolute path into a temp scratchpad, which meant the linter only ran on one
# machine, in one directory, that Windows was free to delete.
BASE = Path(__file__).resolve().parent.parent

REQ = {"title", "id", "status", "description", "references", "author", "date",
       "tags", "logsource", "detection", "level"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
KW = {"and", "or", "not", "of", "them", "all", "1", "2", "3", "x"}


class DupKeyLoader(yaml.SafeLoader):
    pass


def _no_dup(loader, node, deep=False):
    m = {}
    for k, v in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in m:
            raise yaml.YAMLError(f"duplicate key: {key}")
        m[key] = loader.construct_object(v, deep=deep)
    return m


DupKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dup)

issues = []


def flag(f, msg):
    issues.append((str(Path(f).relative_to(BASE)).replace("\\", "/"), msg))


# pass 1: collect all base rule names so correlations can be checked against them
names = set()
files = sorted(glob.glob(str(BASE / "rules" / "**" / "*.yml"), recursive=True))
for f in files:
    for d in yaml.safe_load_all(open(f, encoding="utf-8")):
        if isinstance(d, dict) and "name" in d:
            names.add(d["name"])

for f in files:
    try:
        docs = list(yaml.load_all(open(f, encoding="utf-8"), Loader=DupKeyLoader))
    except yaml.YAMLError as e:
        flag(f, f"YAML/dup-key: {e}")
        continue
    for d in docs:
        if not isinstance(d, dict):
            continue
        if "correlation" in d:
            c = d["correlation"]
            for rn in (c.get("rules") or []):
                if rn not in names:
                    flag(f, f"correlation references unknown base name '{rn}'")
            if c.get("type") == "value_count" and "field" not in (c.get("condition") or {}):
                flag(f, "value_count correlation missing condition.field")
            continue
        # base detection rule
        missing = REQ - set(d)
        if missing:
            flag(f, f"missing fields: {sorted(missing)}")
        if d.get("level") not in LEVELS:
            flag(f, f"bad level: {d.get('level')}")
        det = d.get("detection") or {}
        if not isinstance(det, dict) or "condition" not in det:
            flag(f, "detection missing condition")
            continue
        sels = {k for k in det if k != "condition"}
        if not sels:
            flag(f, "detection has no selections")
        cond = str(det["condition"])
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*\*?", cond):
            if tok in KW:
                continue
            if tok.endswith("*"):
                if not any(s.startswith(tok[:-1]) for s in sels):
                    flag(f, f"condition wildcard '{tok}' matches no selection")
            elif tok not in sels:
                flag(f, f"condition references undefined selection '{tok}'")
        # logsource/EventID sanity: a process_creation rule that keys on some
        # other EventID will never route, and nothing else would tell you.
        ls = d.get("logsource") or {}
        if ls.get("category") == "process_creation":
            for s in sels:
                sv = det[s]
                if isinstance(sv, dict) and "EventID" in sv and str(sv["EventID"]) not in ("1", "4688"):
                    flag(f, f"process_creation logsource but selection '{s}' keys "
                            f"EventID={sv['EventID']} (won't route)")

print(f"linted {len(files)} rule files, {len(names)} base names")
if not issues:
    print("CLEAN - no structural issues")
else:
    for n, m in issues:
        print(f"  [{n}] {m}")
sys.exit(1 if issues else 0)
