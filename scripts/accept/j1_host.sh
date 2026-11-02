#!/bin/sh
# Host setup for the J1 verification job (design v2.2 section 2, "J1 的隔離要求"), run as the
# runner account before any secret is used:
#
#     CW_PRIVATE=<abs dir, must not exist> CW_CAIRNWORK_REF=<40-hex> sh j1_host.sh
#
# 1. GitHub-hosted runner only.
# 2. CW_PRIVATE: a size-capped tmpfs, mode 0700, owned by the runner account. Everything J1
#    keeps (keys, tests, state, logs) lives here, never under $GITHUB_WORKSPACE. From here on this
#    script's own output goes to CW_PRIVATE/host.log (0600).
# 3. bubblewrap, and an AppArmor profile granting user namespaces to bwrap alone (no global
#    sysctl lift).
# 4. Cairnwork at the pinned commit, installed into CW_PRIVATE (owner only).
# 5. The verifier account, made by Cairnwork's own script; its interpreter is the system Python
#    with pytest installed from hash-pinned wheels (verifier-requirements.txt).
# 6. The verifiers' run root on a size-capped tmpfs (the write-volume limit).
# 7. A host firewall rule: no outbound traffic for the verifier account's uid (IPv4 and IPv6).
# 8. No other-writable directory or regular file left on the host's file systems except sticky
#    shared directories (/tmp kind): the hosted image ships 0777 trees (/opt, /usr/share,
#    /usr/local/bin, ...) the verifier account could otherwise change.
set -eu

[ "${RUNNER_ENVIRONMENT:-}" = "github-hosted" ] || { echo "not a GitHub-hosted runner" >&2; exit 1; }
P="${CW_PRIVATE:?}"
REF="${CW_CAIRNWORK_REF:?}"
case "$P" in /*) : ;; *) exit 1 ;; esac
case "$REF" in *[!0-9a-f]*) exit 1 ;; esac
[ "${#REF}" -eq 40 ] || exit 1
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT=/var/lib/cairnwork

umask 077
mkdir "$P"
sudo -n mount -t tmpfs -o "size=6g,mode=0700,uid=$(id -u),gid=$(id -g),nosuid,nodev" tmpfs "$P"
exec >>"$P/host.log" 2>&1
set -x

sudo -n apt-get update -q
sudo -n apt-get install -y -q bubblewrap
# An AppArmor profile that grants userns to bwrap only (Cairnwork docs/SECURITY.md: an end user's
# machine loads a profile; the global sysctl lift stays off).
sudo -n tee /etc/apparmor.d/cairnwork-bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

profile cairnwork-bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/cairnwork-bwrap>
}
PROFILE
sudo -n apparmor_parser -r /etc/apparmor.d/cairnwork-bwrap
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1

export UV_CACHE_DIR="$P/uv-cache" UV_NO_CONFIG=1
src="$P/cw-src"
mkdir "$src"
git -C "$src" init -q
git -C "$src" fetch -q --depth 1 -- https://github.com/cairnwork/cairnwork.git "$REF"
git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD
test "$(git -C "$src" rev-parse HEAD)" = "$REF"
uv sync --frozen --no-dev --project "$src" --python /usr/bin/python3

sudo -n sh "$src/scripts/setup_verifier_user_linux.sh" "$USER"

umask 027
uv venv --quiet --python /usr/bin/python3 "$ROOT/venv"
uv pip install --python "$ROOT/venv/bin/python" --require-hashes --only-binary :all: --no-deps \
  -r "$HERE/verifier-requirements.txt"
"$ROOT/venv/bin/python" -I -c "import pytest"
umask 077

gid="$(getent group cairnwork | cut -d: -f3)"
sudo -n mount -t tmpfs -o "size=4g,mode=2750,uid=$(id -u),gid=$gid,nosuid,nodev" tmpfs "$ROOT/runs"

uid="$(id -u cairnwork-verifier)"
for table in iptables ip6tables; do
  sudo -n "$table" -I OUTPUT -m owner --uid-owner "$uid" -j REJECT
done
for fs in / /dev /run /mnt; do
  [ -d "$fs" ] || continue
  sudo -n find "$fs" -xdev \( -type d ! -perm -1000 -o -type f \) -perm -0002 -print0 \
    | sudo -n xargs -0 -r chmod o-w
done
echo "host setup done"
