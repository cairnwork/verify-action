"""Last step of J1: the only thing J1 shows publicly.

    python3 -I j1_emit.py <private dir>

Reads ``<private>/result.json`` (written by j1_verify.py), checks it again with ``j1_result``,
prints that one line and writes it as the step output ``result`` (job output for J2). With no
result, or one that does not pass the check, it prints nothing, writes nothing and exits 1, so the
job fails and J2 reports ``J1_INCOMPLETE``. Stdlib only; never prints input text or a traceback.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import j1_result as jr  # noqa: E402


def emit(private: Path, output: Path | None) -> int:
    try:
        fd = os.open(private / "result.json", os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(2048)
        text = raw.decode("ascii").rstrip("\n")
    except (OSError, UnicodeDecodeError):
        return 1
    result = jr.parse(text) if "\n" not in text else None
    if result is None:
        return 1
    line = jr.render(result)
    if output is not None:
        with open(output, "a", encoding="ascii") as handle:  # GITHUB_OUTPUT, one plain line
            handle.write(f"result={line}\n")
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not os.path.isabs(argv[0]):
        return 1
    output = os.environ.get("GITHUB_OUTPUT")
    return emit(Path(argv[0]), Path(output) if output else None)


if __name__ == "__main__":
    try:
        sys.stderr = open(os.devnull, "w")  # noqa: SIM115
    except OSError:
        pass
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # noqa: BLE001 - never a traceback
        sys.exit(1)
