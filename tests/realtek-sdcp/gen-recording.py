#!/usr/bin/env python3
"""Generate custom.pcapng: a synthetic usbmon recording of a 2c0a:5816 reader.

The device side is simulated from the protocol observed on the real reader
(see docs/protocol.md), with libfprint's virtual-sdcp key material standing in
for the device keys. libfprint runs SDCP with fixed host keys/nonces in
emulation mode (FP_DEVICE_EMULATION=1), so the whole exchange is deterministic
and can be replayed with umockdev against the realtek_sdcp driver.

Usage: gen-recording.py /path/to/libfprint-source [output.pcapng]
"""
import hashlib
import hmac
import pathlib
import re
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode

src = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else pathlib.Path(__file__).with_name("custom.pcapng")


# ---------------------------------------------------------------- test vectors

def hex_consts(path, names):
    text = path.read_text()
    vals = {}
    for n in names:
        m = re.search(n + r"_hex\[\]\s*=\s*((?:\s*\"[0-9a-fA-F]*\")+)\s*;", text)
        vals[n] = bytes.fromhex("".join(re.findall(r"\"([0-9a-fA-F]*)\"", m.group(1))))
    return vals


def c_array(path, name):
    m = re.search(r"%s\[\] = \{([^}]*)\}" % name, path.read_text())
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))


v = hex_consts(src / "libfprint/drivers/virtual-sdcp/virtual-sdcp.h",
               ["firmware_private_key", "device_random", "model_certificate", "device_public_key",
                "firmware_public_key", "firmware_hash", "model_signature", "device_signature"])
base = src / "libfprint/fpi-sdcp-device.c"
host_public_key = c_array(base, "test_host_public_key")
host_random = c_array(base, "test_host_random")
identify_nonce = c_array(base, "test_identify_nonce")
pre_enroll_nonce = b"RTK-SDCP-pre-enroll-nonce-test01"   # driver's emulation constant
enroll_nonce = bytes(range(0xa0, 0xc0))                    # what the "device" hands out


# ---------------------------------------------------------------- SDCP device side

def kdf(key, label, context, length):
    return KBKDFHMAC(algorithm=hashes.SHA256(), mode=Mode.CounterMode, length=length, rlen=4, llen=4,
                     location=CounterLocation.BeforeFixed, label=label.encode(), context=context,
                     fixed=None).derive(key)


def mac(secret, label, a=b"", b=b""):
    return hmac.new(secret, label.encode() + b"\0" + a + b, hashlib.sha256).digest()


sk_f = ec.derive_private_key(int.from_bytes(v["firmware_private_key"], "big"), ec.SECP256R1())
pk_h = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), host_public_key)
ms = kdf(sk_f.exchange(ec.ECDH(), pk_h), "master secret", host_random + v["device_random"], 32)
secret = kdf(ms, "application keys", b"", 64)[:32]

claim = (v["model_certificate"] + v["device_public_key"] + v["firmware_public_key"] +
         v["firmware_hash"] + v["model_signature"] + v["device_signature"])
connect_mac = mac(secret, "connect", hashlib.sha256(claim).digest())
enroll_id = mac(secret, "enroll", enroll_nonce)


def lv(b):
    return struct.pack("<H", len(b)) + b


connect_response = (lv(v["device_random"]) + lv(claim) + lv(connect_mac)).ljust(0x4b6, b"\0")

SLOTS, SLOT_LEN = 10, 52
empty_table = bytes(SLOTS * SLOT_LEN)
slot0 = (b"\x01\x01\xf5" + hashlib.sha256(enroll_id).digest() + b"\x00" + b"\xff" * 16)
full_table = slot0 + bytes((SLOTS - 1) * SLOT_LEN)

OK = bytes(5)
FAIL = bytes.fromhex("01f7ffffff")


# ---------------------------------------------------------------- usbmon pcapng

records = []
urb = [0xffff888000000000]
clock = [0]


def usbmon(typ, ep, length, data, df, status):
    clock[0] += 1000
    hdr = struct.pack("<QccBBHccqiiII8siiII", urb[0], typ, b"\x03", ep, 25, 1, b"-", df,
                      clock[0] // 1000000, clock[0] % 1000000, status, length, len(data),
                      bytes(8), 0, 0, 0, 0)
    records.append(hdr + data)


def bulk_out(data):
    urb[0] += 0x40
    usbmon(b"S", 0x01, len(data), data, b"\x00", -115)
    usbmon(b"C", 0x01, len(data), b"", b">", 0)


def bulk_in(data):
    urb[0] += 0x40
    usbmon(b"S", 0x82, 2048, b"", b"<", -115)
    usbmon(b"C", 0x82, len(data), data, b"\x00", 0)


def cmd(c0, c1, p0=0, p1=0, write=None, read=None, status=OK):
    n = len(write) if write is not None else (len(read) if read is not None else 0)
    bulk_out(bytes([c0, c1, p0, p1, 0, 0, 0, 0, 0, 0, n & 0xff, n >> 8]))
    if write is not None:
        bulk_out(write)
    if read is not None:
        bulk_in(read)
    bulk_in(status)


def capture(purpose, accept=bytes(9), polls_without_finger=1):
    cmd(0x05, 0x05, purpose, 0x02)
    for _ in range(polls_without_finger):
        cmd(0x45, 0x06, purpose, 0x02, read=bytes.fromhex("0100000000"))
    cmd(0x45, 0x06, purpose, 0x02, read=bytes.fromhex("00cb820000"))
    cmd(0x45, 0x08, purpose, read=accept, status=OK if accept[0] == 0 else FAIL)


def identify_result(match_id=None, nonce=None):
    if match_id is None:
        return bytes([0x0b]) + bytes(73), FAIL
    return (b"\x00\xf5" + match_id + mac(secret, "identify", nonce, match_id) + bytes(8)), OK


# open
cmd(0x05, 0x13, 0x00)
cmd(0x45, 0x0d, read=bytes([0x0d, SLOTS]))
cmd(0x85, 0x01, write=lv(host_random) + lv(host_public_key))
cmd(0x45, 0x02, read=connect_response)

# clear storage
cmd(0x05, 0x0f, 0xff)

# enroll: pre-identify (no match), nonce, 12 samples (one retry), dup check, commit
capture(0x02)
cmd(0x45, 0x0e, read=empty_table)
cmd(0x85, 0x0b, write=pre_enroll_nonce)
res, st = identify_result()
cmd(0x45, 0x0c, 0x00, 0x02, read=res, status=st)
cmd(0x45, 0x0e, read=empty_table)
cmd(0x45, 0x09, read=enroll_nonce)
for i in range(12):
    if i == 5:
        capture(0x04, accept=bytes.fromhex("02999000002e0d0000"), polls_without_finger=0)
    capture(0x04, accept=bytes.fromhex("00c2e301004f5e0100"), polls_without_finger=0)
cmd(0x45, 0x10, 0x01, read=bytes([0x0b]) + bytes(33), status=FAIL)
cmd(0x45, 0x0e, read=empty_table)
cmd(0x85, 0x0a, 0xf5, write=enroll_id + b"\x00" + b"\xff" * 16)

# list
cmd(0x45, 0x0e, read=full_table)

# verify (match) and identify (match)
for _ in range(2):
    capture(0x02, polls_without_finger=0)
    cmd(0x45, 0x0e, read=full_table)
    cmd(0x85, 0x0b, write=identify_nonce)
    res, st = identify_result(enroll_id, identify_nonce)
    cmd(0x45, 0x0c, 0x00, 0x02, read=res, status=st)

# delete
cmd(0x45, 0x0e, read=full_table)
cmd(0x05, 0x0f, 0x00)


# ---------------------------------------------------------------- write file

def block(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", btype, total) + body + b"\0" * pad + struct.pack("<I", total)


with open(out, "wb") as f:
    f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    f.write(block(1, struct.pack("<HHI", 220, 0, 262144)))
    for i, r in enumerate(records):
        ts = i * 1000
        f.write(block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xffffffff, len(r), len(r)) + r))

print("wrote %s (%d usbmon records)" % (out, len(records)))
