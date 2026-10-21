#!/usr/bin/env python3
# SDCP enroll + verify test for the 2c0a:5816 Realtek fingerprint reader.
#
# The reader runs Microsoft's Secure Device Connection Protocol (SDCP): it only
# stores a fingerprint under an enrollment ID that is HMAC'd with a session key
# from a secure connect handshake. This script reproduces the sequence the
# Windows driver uses (from a USB capture), with libfprint's SDCP crypto:
#   connect (85 01 / 45 02) -> identify (85 0b / 45 0c) ->
#   enrollment nonce (45 09) -> 12 samples ->
#   duplicate check (45 10 01) -> commit (85 0a f5, id || 00 || ff*16) ->
#   identify (85 0b / 45 0c) -> delete the test print's slot.
#
# Needs:  sudo dnf install python3-pyusb python3-cryptography
# Run:    sudo systemctl stop fprintd
#         sudo python3 -u rtk-sdcp-probe.py 2>&1 | tee ~/rtk-sdcp.log
# Options: --keep        don't wipe the test print at the end
#          --samples N   accepted touches before commit (Windows uses 12)

import argparse
import hashlib
import hmac
import os
import sys
import time

import usb.core
import usb.util
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode

VID, PID = 0x2C0A, 0x5816
EP_OUT, EP_IN = 0x01, 0x82
SLOT_LEN = 52        # Windows reads 520 bytes for 10 slots
SUBFACTOR = 0xF5     # WINBIO_FINGER_UNSPECIFIED_POS_01, as sent by Windows

ap = argparse.ArgumentParser()
ap.add_argument("--keep", action="store_true")
ap.add_argument("--samples", type=int, default=12)
ap.add_argument("--windows-test", action="store_true",
                help="first identify the Windows Hello finger (already proven to work)")
ap.add_argument("--wipe-first", action="store_true",
                help="erase ALL prints on the reader first, including Windows Hello")
args = ap.parse_args()


# ---------------------------------------------------------------- SDCP crypto
# Mirrors libfprint's fpi-sdcp.c (verified against its test vectors).

def kdf(key, label, context, length):
    return KBKDFHMAC(algorithm=hashes.SHA256(), mode=Mode.CounterMode, length=length,
                     rlen=4, llen=4, location=CounterLocation.BeforeFixed,
                     label=label.encode(), context=context, fixed=None).derive(key)


def mac(secret, label, a=b"", b=b""):
    return hmac.new(secret, label.encode() + b"\0" + a + b, hashlib.sha256).digest()


def application_secret(sk_h, pk_f, r_h, r_d):
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_f)
    ms = kdf(sk_h.exchange(ec.ECDH(), peer), "master secret", r_h + r_d, 32)
    return kdf(ms, "application keys", b"", 64)[:32]


def self_test():
    sk = ec.derive_private_key(0x8400ED14579CDF11586477E836E8CB52708441C1C2A447C218C5BBC2D118FBC7, ec.SECP256R1())
    s = application_secret(
        sk,
        bytes.fromhex("04083cb5e7ece3a8ffa2b6d2d52e2c1721f7d8de6eaaca7fad08267e289e97eca1"
                      "8f3bf8afe57e528b6ad07023df442621c4ad8294816d12852339848eb1196d16"),
        bytes.fromhex("d877403abe82f4d97e1448c5052d83a532a45e56ef049cbbf981137520e713bf"),
        bytes.fromhex("353eb43ffb422fc96c857140d5c399d588feef46f62bd363b97c823975bb27e7"))
    eid = mac(s, "enroll", bytes.fromhex("c2101c44c9a667bba397e81f48b143398603e2c9335a68b409e1dbe71e005ca2"))
    if (s.hex() != "81cbe5d02ad5185b2296a10a6f951b12cdb580e4cf7db4ed7207a17d62a364f6" or
            eid.hex() != "0b93a18533dc49c514a15a886bdb1d92970291800733ebcfc2db689a9344e6eb"):
        sys.exit("SDCP crypto self-test FAILED (python3-cryptography mismatch).")
    print("SDCP crypto self-test passed.")


def ecdsa_ok(pub, sig, data):
    try:
        pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                   data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------- transport

def hx(b, limit=96):
    s = bytes(b).hex()
    return s if len(s) <= limit else s[:limit] + "...(%d bytes)" % len(b)


def cmd(c0, c1, p0=0, p1=0, data_len=0):
    return bytes([c0, c1, p0, p1, 0, 0, 0, 0, 0, 0, data_len & 0xFF, data_len >> 8])


def read_in(timeout):
    while True:
        buf = dev.read(EP_IN, 4096, timeout=timeout)
        if len(buf):
            return bytes(buf)


def run(c, write_data=None, label="", timeout=5000):
    ctype = (c[0] & 0xC0) >> 6
    dlen = c[10] | (c[11] << 8)
    dev.write(EP_OUT, c, timeout=1000)
    data = None
    if ctype == 2:
        dev.write(EP_OUT, write_data, timeout=5000)
    elif ctype == 1:
        data = read_in(timeout)[:dlen]
    status = read_in(2000)
    if label:
        print("  %-18s cmd=%s%s -> data=%s status=%s" % (
            label, hx(c), (" wdata=" + hx(write_data)) if write_data else "",
            hx(data) if data is not None else "-", hx(status)))
    return data, status


def ok(status):
    return status[0] == 0


def capture(purpose):
    """Start capture, wait for a finger, accept sample. Returns accept status byte and data."""
    run(cmd(0x05, 0x05, purpose, 0x02))
    print("  >> touch the sensor", flush=True)
    while True:
        data, _ = run(cmd(0x45, 0x06, purpose, 0x02, 5))
        if data[0] == 0:
            break
        time.sleep(0.05)
    data, _ = run(cmd(0x45, 0x08, purpose, 0, 9), label="accept-sample")
    return data[0], data


def pause(msg):
    """Let the user lift/switch fingers before the next capture starts."""
    time.sleep(1.0)
    input("  >> %s, then press Enter... " % msg)


def identify(secret, slots):
    """SDCP identify in Windows' order: touch, slot table, nonce, result.
    Returns the matched id (MAC-verified) or None."""
    for _ in range(5):
        st, _ = capture(0x02)
        if st == 0:
            break
        print("  retry (status 0x%02x) - lift and touch again" % st)
    run(cmd(0x45, 0x0E, data_len=SLOT_LEN * slots))
    id_nonce = os.urandom(32)
    run(cmd(0x85, 0x0B, data_len=32), id_nonce, label="identify-nonce")
    res, _ = run(cmd(0x45, 0x0C, 0x00, 0x02, 0x4A), label="identify-result")
    if res[0] != 0:
        print("  identify: no match (status 0x%02x)" % res[0])
        return None
    # layout not yet confirmed: status || [subfactor] || id(32) || mac(32) || ...
    for off in (1, 2):
        rid, rmac = res[off:off + 32], res[off + 32:off + 64]
        if hmac.compare_digest(mac(secret, "identify", id_nonce, rid), rmac):
            print("  identify: MATCH, id %s, MAC verified (id at offset %d)" % (rid.hex(), off))
            return rid
    print("  identify: match reported but MAC did NOT verify at offset 1 or 2: %s" % res.hex())
    return None


def lv(buf, o):
    n = int.from_bytes(buf[o:o + 2], "little")
    return buf[o + 2:o + 2 + n], o + 2 + n


# ---------------------------------------------------------------- main

self_test()

dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None:
    sys.exit("Reader 2c0a:5816 not found.")
dev.reset()
try:
    if dev.is_kernel_driver_active(0):
        dev.detach_kernel_driver(0)
except (NotImplementedError, usb.core.USBError):
    pass
usb.util.claim_interface(dev, 0)

committed = False
our_slot = None
try:
    print("\n=== Init (as Windows) ===")
    # info reads Windows does first: 40 06 <reg> (8-byte read) + vendor control read 07/<reg>
    def info(reg):
        run(cmd(0x40, 0x06, reg, data_len=8))
        print("  info %02x: %s" % (reg, hx(dev.ctrl_transfer(0xC0, 0x07, reg, 0, 8, timeout=1000))))
    info(0x0D)
    run(cmd(0x46, 0x16, data_len=32), label="sensor-id")
    for reg in (0x08, 0x0A, 0x0B, 0x0C):
        info(reg)
    run(cmd(0x46, 0x0E, data_len=1), label="mode-flag")
    info(0x0D)
    run(cmd(0x05, 0x13, 0x00), label="select-os 0")
    data, _ = run(cmd(0x45, 0x0D, data_len=2), label="get-enroll-num")
    slots = data[1]
    table, _ = run(cmd(0x45, 0x0E, data_len=SLOT_LEN * slots), label="get-template")
    used = [i for i in range(slots) if table[i * SLOT_LEN] != 0]
    print("  slots=%d used=%s" % (slots, used))
    for i in used:
        print("  slot %d: %s" % (i, table[i * SLOT_LEN:(i + 1) * SLOT_LEN].hex()))

    print("\n=== SDCP connect ===")
    sk_h = ec.generate_private_key(ec.SECP256R1())
    pk_h = sk_h.public_key().public_bytes(serialization.Encoding.X962,
                                          serialization.PublicFormat.UncompressedPoint)
    r_h = os.urandom(32)
    req = len(r_h).to_bytes(2, "little") + r_h + len(pk_h).to_bytes(2, "little") + pk_h
    _, st = run(cmd(0x85, 0x01, data_len=len(req)), req, label="connect-request")
    if not ok(st):
        sys.exit("Reader rejected the SDCP connect request.")
    resp, st = run(cmd(0x45, 0x02, data_len=0x4B6), label="connect-response")
    r_d, o = lv(resp, 0)
    claim, o = lv(resp, o)
    dev_mac, o = lv(resp, o)
    cert_len = 4 + int.from_bytes(claim[2:4], "big")
    cert_m = claim[:cert_len]
    p = cert_len
    pk_d, pk_f, h_f = claim[p:p + 65], claim[p + 65:p + 130], claim[p + 130:p + 162]
    s_m, s_d = claim[p + 162:p + 226], claim[p + 226:p + 290]
    cert = x509.load_der_x509_certificate(cert_m)
    print("  model cert: %s (issuer %s, expires %s)" % (
        cert.subject.rfc4514_string(), cert.issuer.rfc4514_string(), cert.not_valid_after_utc.date()))
    print("  model signature:  %s" % ("valid" if ecdsa_ok(cert.public_key(), s_m, pk_d) else "INVALID"))
    pub_d = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_d)
    print("  device signature: %s" % ("valid" if ecdsa_ok(pub_d, s_d, b"\xC0\x01" + h_f + pk_f) else "INVALID"))
    secret = application_secret(sk_h, pk_f, r_h, r_d)
    claim_hash = hashlib.sha256(cert_m + pk_d + pk_f + h_f + s_m + s_d).digest()
    if not hmac.compare_digest(mac(secret, "connect", claim_hash), dev_mac):
        sys.exit("  Connect MAC MISMATCH - key derivation differs from this firmware.")
    print("  connect MAC verified -> secure session established")

    r = os.urandom(32)
    _, st = run(cmd(0x85, 0x03, data_len=34), b"\x20\x00" + r, label="reconnect")
    rmac_resp, _ = run(cmd(0x45, 0x04, data_len=34), label="reconnect-mac")
    rmac, _ = lv(rmac_resp, 0)
    print("  reconnect MAC: %s" % ("verified" if hmac.compare_digest(mac(secret, "reconnect", r), rmac) else "MISMATCH"))

    if args.wipe_first and used:
        print("\n=== Wiping all prints on the reader ===")
        run(cmd(0x05, 0x0F, 0xFF), label="wipe-all")
        table, _ = run(cmd(0x45, 0x0E, data_len=SLOT_LEN * slots), label="get-template")
        used = [i for i in range(slots) if table[i * SLOT_LEN] != 0]
        print("  after wipe: used=%s" % used)

    if args.windows_test:
        print("\n=== Identify test: touch with your WINDOWS HELLO finger ===")
        pause("Get your Windows Hello finger ready (not on the sensor yet)")
        hit = identify(secret, slots)
        print("  -> %s" % ("matched the Windows Hello enrollment" if hit else "no match"))

    nonce = None
    for attempt in (1, 2):
        print("\n=== Pre-enroll check (attempt %d): touch with the NEW finger (NOT the Windows Hello one) ===" % attempt)
        pause("Have the NEW finger ready, off the sensor")
        if identify(secret, slots):
            sys.exit("That finger is already enrolled on the reader. Re-run and use a different finger.")
        # Windows asks for the nonce ~2 ms after a no-match identify; do the same, before pausing
        run(cmd(0x45, 0x0E, data_len=SLOT_LEN * slots))
        data, st = run(cmd(0x45, 0x09, data_len=32), label="enroll-nonce")
        if ok(st):
            nonce = data
            break
        print("  enrollment nonce refused (status %s)" % st.hex())
        if attempt == 1:
            print("  -> re-running the SDCP reconnect, then trying once more")
            r = os.urandom(32)
            run(cmd(0x85, 0x03, data_len=34), b"\x20\x00" + r, label="reconnect")
            rmac_resp, _ = run(cmd(0x45, 0x04, data_len=34), label="reconnect-mac")
    if nonce is None:
        sys.exit("Reader refused to issue an enrollment nonce on both attempts.%s" % (
            "" if args.wipe_first or not used else
            " Next test: re-run with --wipe-first (erases the Windows Hello print on the reader)."))

    # Windows starts the first enroll capture right away too, so no pause here
    print("\n=== Enroll: keep using the SAME NEW finger, %d accepted touches (lift between) ===" % args.samples)
    got = tries = 0
    while got < args.samples:
        tries += 1
        if tries > args.samples * 4:
            sys.exit("Too many rejected touches.")
        st, _ = capture(0x04)
        if st == 0:
            got += 1
            print("  sample accepted (%d/%d)" % (got, args.samples))
        else:
            print("  retry (status 0x%02x) - lift and touch again" % st)
        time.sleep(0.6)

    dup, _ = run(cmd(0x45, 0x10, 0x01, data_len=0x22), label="check-duplicate")
    if dup[0] == 0:
        sys.exit("Duplicate check: this finger matches an existing enrollment (id %s). "
                 "Re-run and use a different finger." % dup[2:].hex())
    run(cmd(0x45, 0x0E, data_len=SLOT_LEN * slots), label="get-template")
    enroll_id = mac(secret, "enroll", nonce)
    payload = enroll_id + b"\x00" + b"\xff" * 16
    _, st = run(cmd(0x85, 0x0A, SUBFACTOR, data_len=len(payload)), payload, label="enroll-commit")
    committed = ok(st)
    print("\n*** ENROLL COMMIT %s ***" % ("ACCEPTED" if committed else "REJECTED (status %s)" % st.hex()))

    if committed:
        table, _ = run(cmd(0x45, 0x0E, data_len=SLOT_LEN * slots), label="get-template")
        for i in range(slots):
            rec = table[i * SLOT_LEN:(i + 1) * SLOT_LEN]
            if rec[0]:
                # slot record: valid, ?, subfactor, SHA256(enrollment id), 00, ff*16
                mine = hashlib.sha256(enroll_id).digest() in rec
                if mine:
                    our_slot = i
                print("  slot %d: %s%s" % (i, rec.hex(), "  <- our enrollment (sha256 of id)" if mine else ""))

        print("\n=== Identify: touch once more with the NEW finger ===")
        pause("Lift your finger")
        rid = identify(secret, slots)
        print("  -> %s" % ("matched the NEW enrollment" if rid == enroll_id else
                           "matched a different enrollment" if rid else "no match"))
finally:
    try:
        run(cmd(0x05, 0x07, 0x04), label="cancel-capture")
        if committed and not args.keep:
            if our_slot is not None:
                # delete only the test print's slot; other slots (e.g. Windows Hello) stay
                run(cmd(0x05, 0x0F, our_slot), label="delete-test-print")
            else:
                print("  test print slot not found; left in place")
    except usb.core.USBError as e:
        print("  cleanup error:", e)
    usb.util.release_interface(dev, 0)
    usb.util.dispose_resources(dev)

print("\nDone.")
