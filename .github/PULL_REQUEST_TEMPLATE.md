<!-- Chronolith detection-rule PR. See RULE_SCHEMA.md and CONTRIBUTING.md. -->

## What this rule detects

<!-- One or two sentences: the behaviour, and why it matters to a lean SME team. -->

## Details

- **Rule ID / file:**
- **Category:**
- **MITRE ATT&CK:**
- **Data source:**
- **Severity (`level`):**

## Checklist

- [ ] One rule per file, named `<ID>_<slug>.yml`, in `rules/<category>/`.
- [ ] `id` is a fresh UUID; `status: experimental`; `author` is my GitHub handle.
- [ ] Threshold rules include a correlation document referencing the base `name`.
- [ ] MITRE tags added where applicable.
- [ ] `falsepositives` lists the real benign causes.
- [ ] `tests/<ID>.test.yml` added — at least one fire and one no-fire case.
- [ ] No real customer data anywhere — synthetic placeholders only.
- [ ] Runs cheaply on a lean box (realistic window, no pathological correlation).

## Notes for reviewers

<!-- Anything about tuning, exclusions, or environments where this could be noisy. -->
