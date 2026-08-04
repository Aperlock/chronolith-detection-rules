# chronolith-detection-rules
Chronolith SIEM public detection rules
Community-contributed detection rules for [Chronolith](https://aperlock.com), Aperlock's on-premises AI SIEM.

## What this is

Detection rules ship in Chronolith as structured JSON/YAML data — not executable
code. Rules define event filters, thresholds, and correlation logic; they are
reviewed by Aperlock and shipped to all deployments in signed content updates.
A bad rule can't compromise a deployment, because rules aren't code.

This repository is where the practitioner community proposes new rules. We
review everything that comes in. If we merge it, it ships.

## Status

Chronolith is shipping to founding MSP/VAR and clients early Q4 2026. This repository
is open now so the contribution process, schema, and review workflow are ready
before general availability — rule content will grow as the product approaches
launch.

## How to contribute

1. **Fork this repository.** Clone locally.000
2. **Write your rule** using the schema in `RULE_SCHEMA.md` (coming soon). Map
   to MITRE ATT&CK where applicable. Include test cases in `/tests/`.
3. **Submit a pull request.** We review for false positive rate, performance
   impact, and relevance to Chronolith's actual customer base — target 5
   business days for feedback.
4. **Once merged, it ships** to all Chronolith deployments in the next signed
   content release. Your GitHub handle is credited in the rule metadata. No
   action required on the deployment side.

## What we merge

- Rules relevant to Chronolith's real customer base — lean IT teams at law
  firms, healthcare practices, financial services, manufacturers, and
  MSP-managed SMB clients.
- Rules that map cleanly to MITRE ATT&CK and use the Sigma-compatible format.
- Rules with real test cases, not theoretical coverage.

## What we don't merge

- Rules that require infrastructure most SME clients don't have (dedicated
  honeypot hosts, specific EDR telemetry). Chronolith is not Splunk
  Enterprise.
- Executable extensions of any kind. Rules are data, not code — that's the
  whole safety model.

## Format

Rules are structured YAML. Full schema documentation ships alongside the
first wave of published rules ahead of general availability.

## Questions

partners@aperlock.com · [aperlock.com/detection-rules](https://aperlock.com/detection-rules.html)

---

Aperlock LLC · Chronolith is on-premises, always. Your data never leaves your network.
