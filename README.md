# Cairnwork Verify Action

GitHub composite action to verify offline Cairnwork attestations on pull request commits.

## What it checks

A `VERIFIED` verdict indicates that the attestation for the specified head commit verified offline against the configured public key and the repository history.

Two receipt versions are accepted: v0.1 (a change Cairnwork verified on its own commit) and v0.2 (an external candidate, such as a pull request head, verified with deferred tests; see [v0.2 receipts and `policy`](#v02-receipts-and-policy)).

## Enforcement and trust model

Under standard `pull_request` triggers, GitHub Actions runs the workflow file from the pull request's head ref, including on forks. A pull request author could modify `.github/workflows` to set `require-when: never` or point `public-key` to their own keypair, and the resulting check run would still satisfy branch protection rules matched by name.

The only enforcing configurations are:

1. **Repository ruleset "Required workflow":** Configure a GitHub repository ruleset requiring a verification workflow sourced from a protected ref. GitHub Actions evaluates and executes the workflow definition from the protected ref, ignoring changes within the pull request branch.
2. **Workflow on `pull_request_target`:** Run the workflow from the base branch context via `pull_request_target`. This configuration is acceptable here only because this action executes no code from the repository under test; it only reads git objects and runs the pinned verifier. The workflow fetches the PR head commit objects without checking out or running code from the PR ref, keeping `permissions: contents: read`. Do not add steps that check out or run anything from the PR head to such a workflow:

```yaml
name: Cairnwork Attestation Check

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout base repository
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          fetch-depth: 0

      - name: Fetch PR head objects (no checkout, nothing from the PR is executed)
        run: git fetch origin "+refs/pull/${{ github.event.pull_request.number }}/head:refs/remotes/origin/pr-head"

      - name: Verify attestation
        uses: cairnwork/verify-action@<commit-sha>
        with:
          candidate: ${{ github.event.pull_request.head.sha }}
          base: ${{ github.event.pull_request.base.sha }}
          public-key: ${{ vars.CAIRNWORK_PUBLIC_KEY }}
          cairnwork-ref: '<40-hex-commit-sha>'
```

Never use `GITHUB_SHA` on `pull_request` (that is the merge commit). The action requires the pull request head commit as the candidate commit.

## How the bundle reaches the PR

Attestation bundles are stored in git notes under `refs/notes/cairnwork`. Notes are created and pushed by the attesting host using its own write access to the base repository — not by the pull request author. Because notes reside on the base repository, pull requests submitted from external forks are supported.

To attach and publish an attestation bundle:

```bash
git notes --ref cairnwork add -F bundle.json <candidate>
git push origin refs/notes/cairnwork
```

When `fetch-notes` is `true`, the action runs `git fetch origin "+<notes-ref>:<notes-ref>"`. If the notes ref does not exist on origin, `git fetch` exits non-zero (`fatal: couldn't find remote ref ...`), which triggers the `NOTES_FETCH_FAILED` error when verification is required. If git fetch exits 0 with nothing fetched, the action falls through to `BUNDLE_MISSING`.

## Keys

Prefer a repository or organization variable holding the PEM text (`${{ vars.CAIRNWORK_PUBLIC_KEY }}`). If the key is kept as a file on a protected branch, copy it out of the checkout first (for example to `$RUNNER_TEMP`) in a step that runs before the action, and pass that absolute path — files inside `repo-path` are rejected with `BAD_INPUT`:

```yaml
- name: Copy public key
  run: cp .github/cairnwork-public-key.pem "$RUNNER_TEMP/cairnwork-public-key.pem"
```

Never trust a public key committed in the pull request under review: an untrusted pull request author could supply their own keypair alongside an unauthorized attestation. When `public-key` or `core-identity` are given as file paths, they must be absolute paths and must not resolve (via `realpath`) to any path inside `repo-path` (the PR checkout); otherwise the action fails with `BAD_INPUT`. Inline PEM text is unaffected by this path restriction.

Multiple keys may be supplied as PEM text separated by blank lines or as a newline-separated list of absolute file paths. The action attempts verification with each key in sequence until one succeeds, reporting the final error code if all fail.

Published keys are listed by `keyid` (the SHA-256 of the raw Ed25519 key, the value in the bundle's signature) at <https://cairnwork.github.io/keys/>, each served as `/keys/<keyid>.pem`. Only a demo drill key is listed today. To rotate, add the new key next to the old one in `vars.CAIRNWORK_PUBLIC_KEY` before the attesting host starts signing with it, and remove the old key only once no pull request still needs an attestation signed by it.

## v0.2 receipts and `policy`

A v0.2 receipt binds the pull request head, the base, the deferred test commit and the tree the verifiers ran. `cairnwork-attest verify` checks it in one of two modes, chosen by whether `repo-path` holds the test commit:

- **full**: the test commit is in the repository; the executed tree is rebuilt from head and tests and must match.
- **confidential**: the test commit is not in the repository (the tests stay private). A `policy` is required; without one the receipt is rejected with `POLICY_REQUIRED`. The test contents are the signer's word in this mode.

The policy is the receiver's own configuration, never taken from the pull request or the receipt: strict JSON with `rule`, `test_commit`, `core_identity` and `key_id` (and optional keys), as defined by Cairnwork's `docs/ATTESTATION.md` ("Verifying a v0.2 receipt"). Pass it as JSON text (for example `${{ vars.CAIRNWORK_POLICY }}`) or as an absolute file path outside `repo-path`, as for `public-key`. This action only checks that it is a JSON object; `cairnwork-attest` checks the rest, and a policy it cannot use fails with `VERIFIER_ERROR`.

Under a policy, the signing key must be the one the policy pins (`SIGNATURE_INVALID`), and the receipt's test commit and rule must be the policy's (`TEST_SOURCE_MISMATCH`). A v0.1 receipt binds no tests, so it fails under a policy with `TEST_SOURCE_MISMATCH`. Without a policy, a receiver cannot tell whether tests were required: set `policy` whenever tests are. A v0.2 receipt for another commit is reported as `CANDIDATE_MISMATCH`, as for v0.1.

v0.2 receipts and the `policy` input need a `cairnwork-ref` that supports them (the first is `85214150ba903d4126acae73223e965d5e8e1ecc`; pin the cairnwork commit the attesting host uses). Older commits reject a v0.2 receipt as `STATEMENT_SHAPE` and a policy with `VERIFIER_ERROR`.

## Requirement conditions (`require-when`)

The default requirement condition is `always` (fail-closed).

The `label:<name>` condition is ADVISORY ONLY: it requires the workflow trigger to subscribe to `types: [opened, synchronize, reopened, labeled, unlabeled]`, and anyone who can edit labels can skip the check. Never use `label:<name>` as a required check in branch protection.

## Base commit checks (`check-base`)

Accepted values for `check-base` are:
- `ancestor` (default, aliased by `true`): requires `predicate.base_commit` to be an ancestor of (or equal to) the PR `base` commit.
- `exact`: requires `predicate.base_commit` to equal the PR `base` commit SHA exactly.
- `false`: skips the base commit check.

Trade-off: `ancestor` allows the target branch to advance after an attestation is issued without failing verification, but hidden tests or policies updated on the target branch after attestation are not covered. `exact` is strict and requires the attestation to have been produced against the current tip of the target branch.

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `candidate` | 40-hex commit SHA to verify. | No | `${{ github.event.pull_request.head.sha }}` |
| `base` | 40-hex tip commit SHA of the PR target branch. | No | `${{ github.event.pull_request.base.sha }}` |
| `bundle-path` | Path to a bundle file. If empty, reads from git notes. | No | `""` |
| `notes-ref` | Git notes ref containing attestations. | No | `refs/notes/cairnwork` |
| `fetch-notes` | Fetch notes ref from origin before verification. | No | `true` |
| `public-key` | Path to PEM file (absolute, outside `repo-path`) or PEM text. | Yes | — |
| `core-identity` | Optional path to Core identity JSON pin file (absolute, outside `repo-path`). | No | `""` |
| `policy` | Receiver policy for v0.2 receipts: JSON text, or a file path (absolute, outside `repo-path`). Required in confidential mode. | No | `""` |
| `cairnwork-ref` | 40-hex commit of `cairnwork/cairnwork` to install (must be at or after `5819a8c56e19fb32d597f8213a9961f46c3307d4`). | Yes | — |
| `python-version` | Python version used for cairnwork virtual environment. | No | `3.12` |
| `require-when` | Requirement condition: `always`, `never`, or advisory `label:<name>`. | No | `always` |
| `pr-labels` | JSON array of pull request label names. | No | `${{ toJSON(github.event.pull_request.labels.*.name) }}` |
| `repo-path` | Path to checked-out repository. | No | `.` |
| `check-base` | Base commit verification mode: `ancestor` (default), `exact`, or `false` (`true` is alias for `ancestor`). | No | `ancestor` |

## Outputs

| Output | Description |
| --- | --- |
| `verdict` | Verification verdict: `VERIFIED`, `REJECTED`, `SKIPPED`, or `ERROR`. |
| `code` | Outcome code (`OK` on success, or a failure/error code). |
| `candidate` | Candidate commit SHA. |
| `base-commit` | Base commit SHA extracted from the statement predicate (empty if unparseable). |
| `statement-sha256` | SHA-256 digest of raw decoded DSSE payload bytes (empty if unparseable). |
| `keyid` | Key ID from the DSSE signature envelope (empty if unparseable or non-whitelisted). |
| `predicate-type` | The statement's `predicateType`, set only when it is a version this action supports (empty otherwise). It is read before the signature is checked, so it is not authenticated: rely on it only when `verdict` is `VERIFIED`. |

## Codes

| Code | Verdict | Description |
| --- | --- | --- |
| `OK` | `VERIFIED` | Attestation verified against public key and git history. |
| `BAD_INPUT` | `ERROR` | Input validation failure (non-40-hex SHA, missing required input, invalid format, non-array `pr-labels`, `policy` not a JSON object, or key or policy path inside `repo-path`). |
| `MISSING_TOOL` | `ERROR` | Required command-line utility (`jq`, `git`, `base64`, `awk`, or at least one of `sha256sum` or `shasum`) is not found on the runner. |
| `INSTALL_FAILED` | `ERROR` | Fetching `cairnwork` repository or syncing virtual environment dependencies via `uv sync` failed. |
| `NOTES_FETCH_FAILED` | `ERROR` | Git fetch of the notes ref from origin failed. |
| `BUNDLE_MISSING` | `REJECTED` / `SKIPPED` | No bundle file or note found for candidate commit (`SKIPPED` when not required). |
| `BUNDLE_MALFORMED` | `REJECTED` | Bundle is not valid DSSE JSON or statement payload cannot be decoded. |
| `UNSUPPORTED_PREDICATE_TYPE` | `REJECTED` | The statement `_type` is not `https://in-toto.io/Statement/v1`, or its `predicateType` is not one this action version supports (today `https://cairnwork.github.io/attestation/verified-change/v0.1` and `.../v0.2`). Checked before any predicate field is read; upgrade the action to accept a newer predicate version. |
| `BASE_NOT_IN_TARGET` | `REJECTED` | `predicate.base_commit` does not satisfy the `check-base` condition against target `base`. |
| `VERIFIER_ERROR` | `ERROR` | `cairnwork-attest verify` exited with code 2 (usage or IO error), produced malformed/non-JSON stdout, or binary is missing. |
| `<VERIFIER_CODE>` | `REJECTED` | Verifier rejection code (e.g. `CANDIDATE_MISMATCH`, `SIGNATURE_INVALID`, and for v0.2 `POLICY_REQUIRED`, `TEST_SOURCE_MISMATCH`) parsed from `verify --json` stdout when verifier exits 1. |

Verifier rejection codes (`<VERIFIER_CODE>`) and details are parsed directly from machine-readable `cairnwork-attest verify --json` output.

## What it does not cover

- Hidden tests or policy definitions may have changed on the target branch since the attestation was issued.
- Compromise of the attesting host or its signing keys.
- It does not judge the semantic quality or intent of the commit.

## Pinning

Pin this action by commit SHA rather than mutable tags. Similarly, specify `cairnwork-ref` as a full 40-hex commit SHA; branch and tag names are rejected. The commit must be at or after `5819a8c56e19fb32d597f8213a9961f46c3307d4` (the first with `verify --json`); older commits fail with `VERIFIER_ERROR` because they reject `--json` as an unknown option (argparse exit 2).

## Status

v0. Public since 2026-10-23. Pin by commit SHA; tags are published for convenience (`v0.1.0`) but a SHA is the only immutable reference.
