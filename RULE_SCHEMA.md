# Chronolith Detection Rule Schema

Chronolith detection rules are **[Sigma](https://sigmahq.io)-compatible YAML**.
If you've written a Sigma rule before, you already know most of this. Rules are
**data, not code** — Chronolith reads the filters, thresholds, and correlation
logic below; nothing in a rule ever executes. A bad rule can produce noise, never
a compromise.

This document is the authoring reference. See `rules/` for worked examples and
`tests/` for the test-case format.

---

## 1. Repository layout

```
rules/
  identity/            # Category A — authentication & identity
  privilege/           # Category B — privilege & account management
  defense-evasion/     # Category C — tamper / AV / log evasion
  ransomware/          # Category D — ransomware indicators
  execution-persistence/ # Category E — execution & persistence
  m365/                # Category F — Microsoft 365 / Entra ID
  network/             # Category G — network & firewall
  infrastructure/      # Category H — infrastructure & hardware telemetry
  filesystem/          # Category FS — file & data access (share/file audit)
  lateral-movement/    # Category LM — lateral movement (RDP, SMB, WinRM, WMI, PsExec)
tests/                 # one <rule-id>.test.yml per rule with test cases
```

One rule per file. Name files `<ID>_<short_slug>.yml` (e.g.
`A-001_brute_force_single_account.yml`). IDs are `<Category letter>-<NNN>` — a
single letter for A–H, `FS-<NNN>` for filesystem, `LM-<NNN>` for lateral movement.
Ask in your PR if you're unsure which number is free.

---

## 2. A rule is one file, one or two YAML documents

- **Document 1 — the detection rule** (always): a standard Sigma rule (`logsource`
  + `detection`).
- **Document 2 — a correlation** (only for count/threshold rules): a Sigma
  [correlation](https://github.com/SigmaHQ/sigma-specification) that references
  document 1 by its `name`. This is how "N events in M minutes" is expressed —
  Sigma-native, not a Chronolith invention.

Single-occurrence rules (e.g. "any Domain Admin added") need only document 1.

---

## 3. Detection-rule fields

| Field | Required | Notes |
|---|---|---|
| `title` | ✅ | Short human name. |
| `id` | ✅ | A UUID (v4). Generate one; must be unique in the repo. |
| `name` | for threshold rules | Short referenceable slug; the correlation points at this. |
| `status` | ✅ | `experimental` \| `test` \| `stable`. New PRs start `experimental`. |
| `description` | ✅ | What it detects **and why it matters** to a lean SME IT team. |
| `references` | ✅ | Links — MITRE technique page, advisories. |
| `author` | ✅ | Your GitHub handle. Credited in the shipped rule metadata. |
| `date` | ✅ | `YYYY-MM-DD` first authored. `modified:` when you update. |
| `tags` | ✅ | MITRE ATT&CK: `attack.<tactic>` + `attack.tNNNN[.NNN]` (lower-case). |
| `logsource` | ✅ | Data source — see §4. |
| `detection` | ✅ | Selections + `condition` — standard Sigma. |
| `fields` | optional | Fields worth surfacing to the analyst. |
| `falsepositives` | ✅ | Real benign causes. "None" is almost never true — think hard. |
| `level` | ✅ | `informational` \| `low` \| `medium` \| `high` \| `critical`. This is the alert severity. |

---

## 4. `logsource` — Chronolith data sources

Map to the source Chronolith actually ingests from:

| Chronolith source | `logsource` |
|---|---|
| Windows Security log | `product: windows` / `service: security` |
| Windows System log | `product: windows` / `service: system` |
| Windows process creation (4688 / Sysmon 1) | `product: windows` / `category: process_creation` |
| Microsoft 365 unified audit | `product: m365` / `service: audit` |
| Entra ID sign-ins | `product: m365` / `service: signinlogs` |
| FortiGate / firewall | `product: fortinet` |
| Linux (syslog / journald / auditd) | `product: linux` |

Windows EventIDs go in `detection` as `EventID:`. Don't invent a source that
requires infrastructure most SME clients don't have (dedicated honeypots,
vendor-specific EDR agents) — those PRs are declined. Chronolith is not Splunk
Enterprise.

---

## 5. Thresholds — the correlation document

Count and rate rules use a Sigma correlation. Supported `type`s:

- `event_count` — N matching events in a window (brute force, mass file change).
- `value_count` — N **distinct** values of a field (lateral movement = distinct
  destination hosts; password spray = distinct target accounts).

```yaml
correlation:
  type: event_count            # or value_count
  rules:
    - brute_force_single_account   # the base rule's `name`
  group-by:
    - TargetUserName             # what makes each "case" (account, source IP, host)
  timespan: 5m                   # 30s, 5m, 1h, 24h ...
  condition:
    gte: 10                      # fires at >= 10
    # value_count rules also take a field:
    # field: DestinationHost
    # gte: 5
```

`timespan` units: `s` `m` `h` `d`. Keep windows realistic — a 24h window on a
high-volume event is a performance problem on a lean SME box.

---

## 6. MITRE ATT&CK mapping

Tag every rule you can. Format (lower-case, dotted):

```yaml
tags:
  - attack.credential-access          # tactic
  - attack.t1110.001                  # technique (+ sub-technique)
```

Use the real technique the rule detects, not an aspirational one. Untaggable
rules (pure hygiene/hardware) are fine — omit the technique tag, keep a tactic if
one applies.

---

## 7. Test cases (`tests/<ID>.test.yml`) — required

Every rule needs test cases: sample events that **should** fire it and events
that **shouldn't**. This is how we (and you) know it works and check its false
positive rate. Format:

```yaml
rule: A-001_brute_force_single_account
cases:
  - name: ten failures same account fires
    should_fire: true
    events:                     # a burst of raw events, oldest first
      - { EventID: 4625, TargetUserName: jsmith, IpAddress: 10.0.0.9 }
      # ... repeated to cross the threshold ...
  - name: nine failures does not fire
    should_fire: false
    events:
      - { EventID: 4625, TargetUserName: jsmith, IpAddress: 10.0.0.9 }
```

### High-count thresholds — `events_generator`

Some rules only fire past a large count (e.g. 100+ file reads, 200+ file
modifications). Hand-listing that many events is unreadable, so a case may use a
generator instead of an explicit `events:` list:

```yaml
  - name: 100+ distinct files read in the window fires
    should_fire: true
    events_generator:
      count: 120                 # how many events to synthesize
      window_seconds: 240        # spread them evenly across this window
      template:                  # each event; {{i}} is replaced with the index (0..count-1)
        EventID: 5145
        AccessMask: '0x1'
        SubjectUserName: jsmith
        RelativeTargetName: 'client-{{i}}/privileged-memo.docx'   # {{i}} makes each distinct
```

Use `{{i}}` wherever a field must vary per event (distinct filenames, hosts,
accounts) so `value_count` thresholds are exercised correctly. A case uses
either `events:` or `events_generator:`, not both.

Use only synthetic/sample data. **Never** include a real customer's hostnames,
domains, internal AD names, IPs, or usernames — use obvious placeholders
(`jsmith`, `10.0.0.9`, `example.local`).

---

## 8. Checklist before you open a PR

- [ ] One rule per file, named `<ID>_<slug>.yml`, in the right `rules/<category>/`.
- [ ] `id` is a fresh UUID; `status: experimental`; `author` is your handle.
- [ ] Threshold rules have a correlation doc referencing the base `name`.
- [ ] MITRE tags where applicable.
- [ ] `falsepositives` lists the real benign causes.
- [ ] A `tests/<ID>.test.yml` with at least one fire and one no-fire case.
- [ ] No real customer data anywhere — synthetic placeholders only.

We review for false-positive rate, performance on a lean box, and relevance to
Chronolith's actual customer base. Target 5 business days for first feedback.
