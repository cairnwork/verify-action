# Review record

Independent review records for this action, kept in the repository because the
v0 work landed on `main` directly before the repository was public. Later
changes go through pull requests and carry their records as PR comments.

## v0 (main a073bb00bb7fb3e7d3886e20529b57b1178972f2)

Author: workspace-fe56 (Claude session; implementation drafted by the Agy/Gemini
pool, reviewed and edited by the author). Integration owner: workspace-bb.

- **Independent Claude review** (Claude Opus subagent dispatched by the
  integration owner, not the author): round 1 at 361bf6b REJECT (8 findings:
  keyid output injection via unsigned `signatures[].keyid` and unsanitised
  CR/LF in `GITHUB_OUTPUT`; `label:` default allowed bypass; missing trust
  model for `pull_request`; relative key paths resolving inside the PR
  checkout; label parsing not fail-closed; dependencies not pinned; base check
  mode; `xargs` path trimming). Round 2 at 2d7a91e REJECT only because the
  self-test job was red (note cleanup lacked a git identity). Final:
  **ACCEPT at a073bb00bb7fb3e7d3886e20529b57b1178972f2** (CI run
  39809317519 green, 16 self-test cases).
- **Cross-model review** (Gemini, tool-free, diff embedded, dispatched by the
  integration owner): **ACCEPT at 2d7a91e** with 4 non-blocking points
  (notes fetch failure when not required must skip rather than read stale
  local notes; tool check for awk and sha256sum|shasum; deterministic keyid
  injection assertion; extra BAD_INPUT cases). All four were applied in
  d9b7dc2 and a073bb0; the integration owner judged the remaining delta
  (tests and README only) covered.
- Observed on CI: the verifier rejects a tampered `keyid` as
  `SIGNATURE_INVALID` because it matches signatures by the keyid derived from
  the public key; the wrapper additionally blanks the `keyid` output.

Follow-ups: pin `cairnwork-ref` to a commit ≥ 5819a8c and read
`cairnwork-attest verify --json` instead of scraping text.
