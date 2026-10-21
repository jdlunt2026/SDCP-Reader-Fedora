#!/usr/bin/env bash
# Build libfprint with the realtek_sdcp driver and replay the synthetic USB
# recording in tests/realtek-sdcp/ through umockdev.
#
# The recording uses libfprint's virtual-sdcp test certificate, so the test
# build's copy of the driver additionally trusts the virtual test CA. The
# driver that gets installed only trusts libfprint's Microsoft CA store.
#
# Usage: tests/run-replay-test.sh /path/to/libfprint-source [workdir]
# Needs: meson, ninja, umockdev, python3-gi, python3-cryptography and
#        libfprint's build dependencies.

set -euo pipefail

SRC=$(realpath "$1")
WORK=$(realpath -m "${2:-${TMPDIR:-/tmp}/realtek-sdcp-replay}")
HERE=$(dirname "$(realpath "$0")")
REPO=$(dirname "$HERE")

rm -rf "$WORK"
mkdir -p "$WORK"
cp -a "$SRC" "$WORK/src"
python3 -I "$REPO/driver/integrate.py" "$WORK/src"

DRV="$WORK/src/libfprint/drivers/realtek-sdcp/realtek-sdcp.c"
python3 -I - "$DRV" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('#include "fpi-sdcp-claim.h"\n',
              '#include "fpi-sdcp-claim.h"\n#include "virtual-sdcp-ca-store-resource.h"\n\n'
              'static GResource *\ntest_get_ca_store (FpSdcpDevice *sdcp_device)\n'
              '{\n  static gsize registered = FALSE;\n\n'
              '  if (g_once_init_enter (&registered))\n'
              '    {\n      fpi_virtual_sdcp_ca_store_register_resource ();\n'
              '      g_once_init_leave (&registered, TRUE);\n    }\n'
              '  return fpi_virtual_sdcp_ca_store_get_resource ();\n}\n', 1)
s = s.replace('  sdcp_class->identify = dev_identify;\n',
              '  sdcp_class->identify = dev_identify;\n  sdcp_class->get_ca_store = test_get_ca_store;\n', 1)
open(p, "w").write(s)
EOF

cd "$WORK/src"
meson setup _build -Ddrivers=realtek_sdcp,virtual_sdcp -Dtod=false -Ddoc=false \
    -Dinstalled-tests=false -Dintrospection=true >"$WORK/setup.log" 2>&1 ||
    { tail -30 "$WORK/setup.log"; exit 1; }
ninja -C _build >"$WORK/build.log" 2>&1 || { grep -E 'error|warning' "$WORK/build.log" | head -40; exit 1; }

cd "$HERE/realtek-sdcp"
export GI_TYPELIB_PATH="$WORK/src/_build/libfprint"
export LD_LIBRARY_PATH="$WORK/src/_build/libfprint"
export FP_DEVICE_EMULATION=1
export FP_DRIVERS_ALLOWLIST=realtek_sdcp
export G_MESSAGES_DEBUG=all
export G_DEBUG=fatal-warnings

umockdev-run -d device -p "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-8=custom.pcapng" \
    -- python3 custom.py 2>&1 | tee "$WORK/test.log"
status=${PIPESTATUS[0]}
echo "replay test exit status: $status (log: $WORK/test.log)"
exit "$status"
