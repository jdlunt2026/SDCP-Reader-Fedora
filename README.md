# SDCP-Reader-Fedora

A libfprint driver for the **Realtek USB 2.0 Finger Print Bridge, USB ID
`2c0a:5816`** (reports itself as "Secure BIO Sensor"), with a script that
builds and installs it on Fedora.

This reader uses Windows Hello *Enhanced Sign-in Security* firmware. It only
saves fingerprints over Microsoft's **Secure Device Connection Protocol
(SDCP)**, so libfprint's normal `realtek` driver can scan with it but can never
complete an enrollment. The `realtek_sdcp` driver here speaks SDCP using
libfprint 1.95's built-in SDCP framework. All matching happens on the chip;
the session key, enrollment IDs and match results are checked by libfprint.

See [docs/protocol.md](docs/protocol.md) for how the reader works.

> **AI-written code.** The driver, build scripts, tests, tools and docs in
> this repository were written by Claude (Anthropic's AI) working with the
> repository owner, who supplied the hardware, ran every test on the real
> reader and reviewed the results. The protocol was worked out from USB
> captures and test runs on that one reader. It hasn't been reviewed by the
> libfprint maintainers and isn't submitted upstream. Review it yourself
> before relying on it, especially since it handles authentication.

## Status

| | |
|---|---|
| SDCP connect, certificate/signature/MAC checks | tested on the real reader (Python probe) |
| Enroll, identify, verify | tested on the real reader (Python probe) |
| libfprint driver | builds on libfprint 1.95.2; passes a full replay test (`tests/`) |
| fprintd enroll on Fedora 44 | works on the real reader |
| fprintd verify, GNOME lock screen unlock | works on the real reader |

Tested reader firmware: `bcdDevice 0.08`, model certificate issued by
`Windows Hello 11B0C61D CA 2021`.

## Install (Fedora)

```bash
git clone https://github.com/jdlunt2026/SDCP-Reader-Fedora.git
cd SDCP-Reader-Fedora
./fedora-build.sh
```

Run it as your normal user; it uses `sudo` where needed. It:

1. downloads the libfprint 1.95.2 source (checked against a pinned SHA-256),
2. builds it as an RPM with the `realtek_sdcp` driver added (`packaging/libfprint-sdcp.spec`),
3. installs it, version-locks `libfprint` so updates don't replace it, and restarts fprintd.

Then:

```bash
fprintd-enroll
fprintd-verify
sudo authselect enable-feature with-fingerprint   # login, sudo, lock screen
```

Enrollment takes **14 touches**: one for fprintd's own "already enrolled?"
check, one for the reader's check, then 12 samples.

### One enrollment at a time: clear the reader first

The reader only starts an enrollment while its storage is **empty**. Anything
already stored, whether a Windows Hello fingerprint or an earlier enrollment,
makes it refuse, and `fprintd-enroll` reports `enroll-unknown-error`. Clear it
first. This also deletes Windows Hello fingerprints stored on the reader:

```bash
sudo systemctl stop fprintd
sudo python3 tools/fingerprint-clear-storage.py
sudo systemctl start fprintd
fprintd-enroll
```

That means one enrolled finger at a time for now. If you re-enroll, clear the
reader and also remove fprintd's old record with `fprintd-delete $USER`.

### Undo

```bash
./fedora-build.sh --revert
```

This removes the lock and goes back to Fedora's libfprint. Fingerprints enrolled
with this driver won't work with Fedora's libfprint.

## Repository layout

| Path | What |
|---|---|
| `driver/realtek-sdcp/realtek-sdcp.c` | the libfprint driver |
| `driver/integrate.py` | adds the driver to a libfprint ≥ 1.95 source tree, plus two small compatibility fixes (see below) |
| `packaging/libfprint-sdcp.spec` | RPM spec used by `fedora-build.sh` |
| `fedora-build.sh` | build/install/revert script |
| `tests/run-replay-test.sh` | builds libfprint and replays `tests/realtek-sdcp/custom.pcapng` with umockdev |
| `tests/realtek-sdcp/` | synthetic USB recording, its generator and the libfprint test script |
| `tools/rtk-sdcp-probe.py` | standalone Python SDCP enroll/identify test over raw USB |
| `tools/fingerprint-clear-storage.py` | list and wipe the prints stored on the reader |
| `tools/usbpcap-parse.py` | parse a Windows USBPcap capture |

### libfprint source and fixes

The build uses libfprint `1.95.2+tod1` (the source Ubuntu ships), the first
libfprint with the SDCP framework. `integrate.py` also applies two small fixes
to it:

- **TOD guards:** that source calls the TOD (third-party driver) loader even
  when built with `-Dtod=false` and then fails to link; the calls are wrapped
  in `#if HAVE_LIBFPRINT_TOD`.
- **SDCP KDF context:** `fpi_sdcp_kdf()` passes its two context parts as two
  OpenSSL `INFO` parameters. OpenSSL 3.0.x keeps only the first, which breaks
  SDCP key derivation; the parts are now concatenated into one parameter, which
  gives the same result on every OpenSSL version. (Fedora's OpenSSL 3.5 wasn't
  affected.)

## Tests

```bash
tests/run-replay-test.sh /path/to/libfprint-v1.95.2+tod1
```

This builds libfprint with the driver and replays a full open → clear → enroll
(with one rejected sample) → list → verify → identify → delete → close session
through umockdev. umockdev checks every byte the driver sends. The recording is
synthetic: it's generated from the protocol by
`tests/realtek-sdcp/gen-recording.py`, with libfprint's virtual-sdcp test keys
standing in for the reader's, so the test build trusts the virtual test CA. The
installed driver only trusts libfprint's Microsoft CA store.

## Licence

The driver is LGPL-2.1-or-later, like libfprint.
