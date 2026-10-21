# Realtek 2c0a:5816 "Secure BIO Sensor" protocol

Worked out from a Windows Hello USB capture (Wireshark + USBPcap) and tested
on the real reader with `tools/rtk-sdcp-probe.py`.

The reader is a Realtek 5816 match-on-chip sensor, the same family as the
`0bda:5813`/`0bda:5816` readers handled by libfprint's `realtek` driver, but
running Windows Hello **Enhanced Sign-in Security** firmware. That firmware
implements Microsoft's [Secure Device Connection Protocol (SDCP)][sdcp] and
refuses to store a fingerprint unless the enrollment ID is bound to an SDCP
session. The plain `realtek` driver's enroll commit (`85 21`) therefore always
fails with status `01 f7ffffff` (-9).

[sdcp]: https://github.com/microsoft/SecureDeviceConnectionProtocol/wiki

## Transport

| | |
|---|---|
| Interface | 0, vendor class ff/02 |
| Command endpoint | bulk OUT `0x01` |
| Response endpoint | bulk IN `0x82` |
| Also present (unused) | interrupt IN `0x83`, `0x84` |

Each command is a 12-byte header:

```
cmd[0..1]  param[2..5]  addr[6..9]  data_len[10..11] (LE)
```

Bits 7..6 of `cmd[0]` give the data phase: `00` none, `01` device→host read
of `data_len` bytes, `10` host→device write of `data_len` bytes. Every command
ends with a 5-byte status on `0x82`: `00 00000000` on success, otherwise
`01` followed by an error code (`f7ffffff` = -9 is the generic "no"). The
device sends zero-length packets between phases; skip them.

## Commands

| Command | Data | Meaning |
|---|---|---|
| `05 13 <os>` | – | Select OS; Windows uses `00` |
| `45 0d` | read 2 | Template count: `[?, slots]` (10 slots) |
| `45 0e` | read 52×slots | Slot table (see below) |
| `05 0f <slot>` | – | Delete slot; `ff` = delete all |
| `05 05 <purpose> 02` | – | Start capture (purpose `02` identify, `04` enroll) |
| `45 06 <purpose> 02` | read 5 | Poll capture: byte 0 = `00` once a finger was captured |
| `45 08 <purpose>` | read 9 | Accept sample: byte 0 = `00` good, `01`–`0a` retry reasons |
| `05 07 <purpose>` | – | Cancel capture |
| `40 06 <reg>` + vendor ctrl `c0 07 <reg>` | read 8 | Info registers (Windows reads `0d 08 0a 0b 0c`) |
| `46 16` | read 32 | Sensor ID |
| `46 0e` | read 1 | Mode flag (`01`) |

### SDCP commands

| Command | Data | Meaning |
|---|---|---|
| `85 01` | write 101 | ConnectRequest: `[len] r_h(32) [len] pk_h(65)` |
| `45 02` | read 0x4b6 | ConnectResponse: `[len] r_d [len] claim [len] mac`, zero padded |
| `85 03` | write 34 | Reconnect: `[len] r(32)` |
| `45 04` | read 34 | Reconnect MAC: `[len] mac(32)` |
| `85 0b` | write 32 | Identify nonce |
| `45 0c 00 02` | read 0x4a | Identify result: `status, subfactor, id(32), mac(32), …`; status `0b` = no match |
| `45 09` | read 32 | Enrollment nonce |
| `45 10 01` | read 0x22 | Duplicate check: `00 <subfactor> id…` if the finger is already enrolled, `0b` if not |
| `85 0a f5` | write 49 | Enroll commit: `id(32) 00 ff×16`; `f5` = WINBIO_FINGER_UNSPECIFIED_POS_01 |

Lengths in `[len]` are 2 bytes, little endian. The claim is
`cert_m(DER) || pk_d(65) || pk_f(65) || h_f(32) || s_m(64) || s_d(64)`;
the crypto is standard SDCP (ECDH P-256 with `pk_f`, SP800-108 HMAC-SHA256 KDF,
HMAC-SHA256 MACs), identical to libfprint's `fpi-sdcp.c`.

The model certificate is `CN=Secure BIO Sensor`, issued by
`Windows Hello 11B0C61D CA 2021`, which chains to a Microsoft root in
libfprint's SDCP CA store. It expired on 2025-08-16; Windows ignores the
validity period and so does the driver (`NO_CHECK_TIME`). All other checks
(chain, model signature, device signature, connect MAC) stay on.

### Slot table record (52 bytes)

```
00     valid flag (01 = used)
01     01
02     subfactor (f5)
03..34 SHA256(enrollment id)
35     00
36..51 ff × 16
```

The table never holds the enrollment ID itself, only its SHA-256.

## Sequences

**Open:** `05 13 00`, `45 0d`, then SDCP connect (`85 01`, `45 02`) or reconnect (`85 03`, `45 04`).

**Identify / verify:** `05 05 02 02`, poll `45 06 02 02` until byte 0 is `00`,
`45 08 02`, `45 0e`, `85 0b <nonce>`, `45 0c 00 02`.

**Enroll:** the enrollment nonce (`45 09`) is only issued immediately after an
identify that returned "no match", so enrollment is:

1. identify sequence as above, must return `0b` (no match)
2. `45 0e`, `45 09` (nonce)
3. 12 × (`05 05 04 02`, poll `45 06 04 02`, `45 08 04`), retrying rejected samples
4. `45 10 01` duplicate check, `45 0e`
5. `85 0a f5` with `id = HMAC-SHA256(s, "enroll\0" || nonce)`

On the tested reader the nonce was refused every time a print was stored
(whether from Windows Hello or an earlier Linux enrollment) and issued every
time the storage was empty. So this firmware, as driven here, holds one
enrollment at a time; clear the storage (`05 0f ff`) before enrolling. How
Windows adds a second finger is not known yet (the capture only covered an
enrollment into empty storage).
