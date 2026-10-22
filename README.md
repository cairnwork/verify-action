# Cairnwork Verify Action

GitHub composite action to verify offline Cairnwork attestations on pull request commits.

## What it checks

A VERIFIED verdict means the attestation for exactly this head commit verified offline against the given public key and the repository history.

## Usage

```yaml
name: Cairnwork Attestation Check

on:
  pull_request:

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0

      - name: Verify attestation
        uses: cairnwork/verify-action@<commit-sha>
        with:
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

Provide the public key through a repository or organization variable (for example, `${{ vars.CAIRNWORK_PUBLIC_KEY }}`) or read it from a file on a protected branch.

Never trust a public key committed in the pull request under review: an untrusted pull request author could supply their own keypair alongside an unauthorized attestation.

Multiple keys may be supplied as PEM text separated by blank lines or as a newline-separated list of file paths. The action attempts verification with each key in sequence until one succeeds, reporting the final error code if all fail.

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| `candidate` | 40-hex commit SHA to verify. | No | `${{ github.event.pull_request.head.sha }}` |
| `base` | 40-hex tip commit SHA of the PR target branch. | No | `${{ github.event.pull_request.base.sha }}` |
| `bundle-path` | Path to a bundle file. If empty, reads from git notes. | No | `""` |
| `notes-ref` | Git notes ref containing attestations. | No | `refs/notes/cairnwork` |
| `fetch-notes` | Fetch notes ref from origin before verification. | No | `true` |
| `public-key` | Path to PEM file or PEM text (starts with `-----BEGIN PUBLIC KEY-----`). | Yes | — |
| `core-identity` | Path to Core identity JSON pin file. | No | `""` |
| `cairnwork-ref` | 40-hex commit of `cairnwork/cairnwork` to install. | Yes | — |
| `require-when` | Requirement condition: `always`, `never`, or `label:<name>`. | No | `label:cairnwork` |
| `pr-labels` | JSON array of pull request label names. | No | `${{ toJSON(github.event.pull_request.labels.*.name) }}` |
| `repo-path` | Path to checked-out repository. | No | `.` |
| `check-base` | Require `predicate.base_commit` to be ancestor of (or equal to) `base`. | No | `true` |

## Outputs

| Output | Description |
| --- | --- |
| `verdict` | Verification verdict: `VERIFIED`, `REJECTED`, `SKIPPED`, or `ERROR`. |
| `code` | Outcome code (`OK` on success, or a failure/error code). |
| `candidate` | Candidate commit SHA. |
| `base-commit` | Base commit SHA extracted from the statement predicate (empty if unparseable). |
| `statement-sha256` | SHA-256 digest of raw decoded DSSE payload bytes (empty if unparseable). |
| `keyid` | Key ID from the DSSE signature envelope (empty if unparseable). |

## Codes

| Code | Verdict | Description |
| --- | --- | --- |
| `OK` | `VERIFIED` | Attestation verified against public key and git history. |
| `BAD_INPUT` | `ERROR` | Input validation failure (non-40-hex SHA, missing required input, or invalid format). |
| `INSTALL_FAILED` | `ERROR` | Installation of `cairnwork` CLI via `uv tool install` failed. |
| `NOTES_FETCH_FAILED` | `ERROR` | Git fetch of the notes ref from origin failed. |
| `BUNDLE_MISSING` | `REJECTED` / `SKIPPED` | No bundle file or note found for candidate commit (`SKIPPED` when not required). |
| `BUNDLE_MALFORMED` | `REJECTED` | Bundle is not valid DSSE JSON or statement payload cannot be decoded. |
| `BASE_NOT_IN_TARGET` | `REJECTED` | `predicate.base_commit` is not an ancestor of (or equal to) target `base`. |
| `VERIFIER_ERROR` | `ERROR` | `cairnwork-attest verify` exited with code 2 (usage or IO error). |
| `<VERIFIER_CODE>` | `REJECTED` | Verifier rejection code (e.g. `CANDIDATE_MISMATCH`) when `cairnwork-attest` exits 1. |

## What it does not cover

- Hidden tests or policy definitions may have changed on the target branch since the attestation was issued.
- Compromise of the attesting host or its signing keys.
- It does not judge the semantic quality or intent of the commit.

## Pinning

Pin this action by commit SHA rather than mutable tags. Similarly, specify `cairnwork-ref` as a full 40-hex commit SHA; branch and tag names are rejected.

## Status

v0, private preview.
