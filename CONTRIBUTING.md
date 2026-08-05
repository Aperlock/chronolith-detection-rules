# Contributing to Chronolith Detection Rules

Thanks for helping the community catch more, sooner. Rules here are **data, not
code** — you're proposing YAML filters and thresholds that Aperlock reviews and
ships to every Chronolith deployment in a signed content release.

## The flow

1. **Fork and clone.**
2. **Write your rule** following [`RULE_SCHEMA.md`](RULE_SCHEMA.md). One rule per
   file in the right `rules/<category>/` folder, named `<ID>_<slug>.yml`.
3. **Add test cases** in `tests/<ID>.test.yml` — at least one event set that
   fires and one that doesn't. Rules without tests aren't merged.
4. **Open a PR.** Fill in the template. We target 5 business days for first
   feedback.
5. **Merged rules ship** in the next signed content release, credited to your
   GitHub handle in the rule metadata.

## What gets merged

- Relevant to Chronolith's real customer base — lean IT teams at law firms,
  healthcare practices, financial services, manufacturers, and MSP-managed SMBs.
- Maps cleanly to MITRE ATT&CK, uses the Sigma-compatible format.
- Has real test cases and a thought-through `falsepositives` list.
- Runs cheaply on a lean SME box (sane windows, no pathological correlations).

## What doesn't

- Rules needing infrastructure most SME clients don't have — dedicated honeypots,
  vendor-specific EDR telemetry. Chronolith is not Splunk Enterprise.
- Anything executable. Rules are data; that's the entire safety model.

## Ground rules

- **Never commit real customer data** — no real hostnames, domains, internal AD
  names, IPs, or usernames, in rules or tests. Use obvious placeholders
  (`jsmith`, `10.0.0.9`, `example.local`).
- Start new rules at `status: experimental`.
- Be honest about false positives — it's the most useful part of the rule.

## Licensing and sign-off

- **License.** This repository is licensed under the **Detection Rule License
  (DRL) 1.1** — see [`LICENSE`](LICENSE). It's the same license SigmaHQ uses for
  community detection content: permissive, purpose-built for rules-as-data, and
  it keeps the author attribution you're credited with.
- **Inbound = outbound.** By opening a pull request, you agree that your
  contribution is licensed to the project and its users under the DRL 1.1 — the
  same terms as everything else here. No separate copyright assignment (no CLA).
- **Developer Certificate of Origin (DCO).** Every commit must be signed off,
  certifying you have the right to submit it under the DRL 1.1. It's one line —
  add `-s` to your commit:

  ```
  git commit -s -m "Add rule A-013: ..."
  ```

  This appends `Signed-off-by: Your Name <you@example.com>` to the commit
  message. The full DCO text is at https://developercertificate.org. Don't
  submit rules you don't have the right to share (e.g. an employer's proprietary
  detections without permission).

Questions: partners@aperlock.com
