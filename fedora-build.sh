#!/usr/bin/env bash
# Build and install libfprint 1.95.2 with the realtek_sdcp driver on Fedora.
#
# Usage:
#   ./fedora-build.sh            build, install and version-lock libfprint
#   ./fedora-build.sh --revert   remove the lock and go back to Fedora's libfprint
#
# Run as your normal user (not root); it calls sudo where needed.
# Set LIBFPRINT_TARBALL=/path/to/libfprint_1.95.2+tod1.orig.tar.bz2 to use a
# local copy of the source instead of downloading it.

set -euo pipefail

REPO=$(dirname "$(realpath "$0")")
SRCVER=1.95.2+tod1
TARBALL=libfprint_${SRCVER}.orig.tar.bz2
URL=https://archive.ubuntu.com/ubuntu/pool/main/libf/libfprint/$TARBALL
SHA256=750c066c28b78a034c3a8358b26828e15814fa22ef79cb0603176527e9bfed86
SPEC=libfprint-sdcp.spec
WORK="$HOME/rpmbuild-libfprint-sdcp"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || die "Run this as your normal user, not root."
command -v dnf >/dev/null || die "dnf not found; this script is for Fedora."

lock_pkg() {
    if sudo dnf versionlock add libfprint 2>/dev/null; then
        log "libfprint version-locked (undo with: $0 --revert)"
    else
        warn "dnf versionlock unavailable; adding excludepkgs=libfprint to /etc/dnf/dnf.conf"
        grep -q '^excludepkgs=libfprint$' /etc/dnf/dnf.conf ||
            echo 'excludepkgs=libfprint' | sudo tee -a /etc/dnf/dnf.conf >/dev/null
    fi
}

unlock_pkg() {
    sudo dnf versionlock delete libfprint 2>/dev/null || true
    sudo sed -i '/^excludepkgs=libfprint$/d' /etc/dnf/dnf.conf
}

restart_services() {
    sudo udevadm control --reload || true
    sudo udevadm trigger --subsystem-match=usb || true
    sudo systemctl restart fprintd 2>/dev/null || true
}

if [[ ${1:-} == --revert ]]; then
    log "Removing lock and returning to Fedora's libfprint"
    unlock_pkg
    pkgs=(libfprint)
    rpm -q libfprint-devel >/dev/null 2>&1 && pkgs+=(libfprint-devel)
    sudo dnf -y distro-sync "${pkgs[@]}"
    restart_services
    log "Done. Fingerprints enrolled with the SDCP driver will not work with Fedora's libfprint."
    exit 0
fi

# 1. Is the reader there?
if command -v lsusb >/dev/null && ! lsusb -d 2c0a:5816 >/dev/null; then
    warn "Reader 2c0a:5816 not visible in lsusb. Continuing anyway (the build doesn't need it)."
fi

# 2. Tools. The lock from a previous run hides libfprint from dnf, so lift it
#    for the build and put it back on exit if a patched build is installed.
unlock_pkg
trap 'rpm -q libfprint | grep -q rtksdcp && lock_pkg' EXIT

log "Installing build tools"
sudo dnf -y install rpm-build dnf-plugins-core curl python3 usbutils fprintd fprintd-pam

# 3. Sources: libfprint 1.95.2 (has the SDCP framework) + this repo's driver
mkdir -p "$WORK"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
if [[ -n ${LIBFPRINT_TARBALL:-} ]]; then
    cp "$LIBFPRINT_TARBALL" "$WORK/SOURCES/$TARBALL"
elif [[ ! -f $WORK/SOURCES/$TARBALL ]]; then
    log "Downloading $TARBALL"
    curl -fL --retry 3 -o "$WORK/SOURCES/$TARBALL.part" "$URL"
    mv "$WORK/SOURCES/$TARBALL.part" "$WORK/SOURCES/$TARBALL"
fi
echo "$SHA256  $WORK/SOURCES/$TARBALL" | sha256sum -c --quiet ||
    die "Checksum mismatch for $TARBALL; delete it from $WORK/SOURCES and retry."

tar -czf "$WORK/SOURCES/realtek-sdcp-driver.tar.gz" -C "$REPO" driver
cp "$REPO/packaging/$SPEC" "$WORK/SPECS/$SPEC"

# 4. Build
log "Installing build dependencies"
sudo dnf -y builddep "$WORK/SPECS/$SPEC"

log "Building libfprint with realtek_sdcp (a few minutes)"
rm -rf "$WORK/RPMS"/*
rpmbuild -bb --nocheck --define "_topdir $WORK" "$WORK/SPECS/$SPEC"

# 5. Install
mapfile -t RPMS < <(find "$WORK/RPMS" -name 'libfprint-[0-9]*rtksdcp*.rpm')
[[ ${#RPMS[@]} -eq 1 ]] || die "Expected one built libfprint RPM, found ${#RPMS[@]}"
if rpm -q libfprint-devel >/dev/null 2>&1; then
    mapfile -t -O 1 RPMS < <(find "$WORK/RPMS" -name 'libfprint-devel-[0-9]*rtksdcp*.rpm')
fi

log "Installing ${RPMS[*]##*/}"
sudo dnf -y install --allowerasing "${RPMS[@]}"
lock_pkg
restart_services

log "Installed: $(rpm -q libfprint)"

if python3 -c 'import gi' 2>/dev/null; then
    python3 - <<'EOF' || true
import gi
gi.require_version("FPrint", "2.0")
from gi.repository import FPrint
ctx = FPrint.Context()
ctx.enumerate()
devs = [d for d in ctx.get_devices()]
print("Detected readers:", ", ".join("%s (%s)" % (d.get_name(), d.get_driver()) for d in devs) or "none")
EOF
fi

cat <<EOF

Next steps:
  1. Enroll a finger:        fprintd-enroll
  2. Test it:                fprintd-verify
  3. Enable for login/sudo:  sudo authselect enable-feature with-fingerprint

If enrollment fails with "The reader refused to start an enrollment", a print
stored by another system (e.g. Windows Hello) is probably blocking it. Clear the
reader's storage (this also removes Windows Hello prints on the reader):
  sudo systemctl stop fprintd
  sudo python3 $REPO/tools/fingerprint-clear-storage.py

To undo everything:  $0 --revert
EOF
