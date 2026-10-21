#!/usr/bin/env python3
# Minimal pcapng + USBPcap (Windows Wireshark capture) parser, used to work out
# the reader's protocol from a Windows Hello session.
#
# Usage:
#   usbpcap-parse.py capture.pcapng find                       list USB devices (bus/dev/iface)
#   usbpcap-parse.py capture.pcapng dump BUS DEV [IFACE]       traffic of one device (truncated)
#   usbpcap-parse.py capture.pcapng full BUS DEV [IFACE]       same, full payloads
import struct
import sys

path = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "find"
data = open(path, "rb").read()

linktypes = []
packets = []  # (ts, iface, bytes)
off = 0
endian = "<"
while off + 12 <= len(data):
    btype, blen = struct.unpack_from(endian + "II", data, off)
    if btype == 0x0A0D0D0A:
        bom = struct.unpack_from("<I", data, off + 8)[0]
        endian = "<" if bom == 0x1A2B3C4D else ">"
        btype, blen = struct.unpack_from(endian + "II", data, off)
        linktypes = []
    elif btype == 1:
        linktypes.append(struct.unpack_from(endian + "H", data, off + 8)[0])
    elif btype == 6:
        iface, tsh, tsl, cap, orig = struct.unpack_from(endian + "IIIII", data, off + 8)
        packets.append((((tsh << 32) | tsl) / 1e6, iface, data[off + 28: off + 28 + cap]))
    if blen < 12:
        break
    off += blen

recs = []
for idx, (ts, iface, p) in enumerate(packets):
    if len(p) < 27:
        continue
    hlen, irp, status, func, info, bus, dev, ep, xfer, dlen = struct.unpack_from("<HQIHBHHBBI", p, 0)
    rec = dict(n=idx + 1, ts=ts, iface=iface, irp=irp, status=status, func=func,
               resp=bool(info & 1), bus=bus, dev=dev, ep=ep, xfer=xfer,
               payload=p[hlen:hlen + dlen], stage=p[27] if hlen >= 28 and xfer == 2 else None)
    recs.append(rec)

if mode == "find":
    for r in recs:
        pl = r["payload"]
        if r["xfer"] == 2 and r["resp"] and len(pl) >= 18 and pl[1] == 1 and pl[0] == 18:
            vid, pid = struct.unpack_from("<HH", pl, 8)
            print("iface %d bus %d dev %d -> %04x:%04x (pkt %d)" % (r["iface"], r["bus"], r["dev"], vid, pid, r["n"]))
    sys.exit()

bus, dev = int(sys.argv[3]), int(sys.argv[4])
iface = int(sys.argv[5]) if len(sys.argv) > 5 else None
t0 = None
for r in recs:
    if r["bus"] != bus or r["dev"] != dev or (iface is not None and r["iface"] != iface):
        continue
    if t0 is None:
        t0 = r["ts"]
    pl = r["payload"]
    kind = {0: "ISO", 1: "INT", 2: "CTL", 3: "BLK"}.get(r["xfer"], "?")
    if r["xfer"] == 3:
        out = not (r["ep"] & 0x80)
        # OUT data rides on the request; IN data on the completion
        if out and r["resp"]:
            continue
        if not out and not r["resp"]:
            continue
        if not pl and not (r["status"]):
            if not out:
                print("%9.3f #%-6d %s IN  ep%02x (zlp)" % (r["ts"] - t0, r["n"], kind, r["ep"]))
            continue
        print("%9.3f #%-6d %s %s ep%02x len=%-4d st=%08x %s" % (
            r["ts"] - t0, r["n"], kind, "OUT" if out else "IN ", r["ep"], len(pl), r["status"],
            pl.hex() if mode == "full" or len(pl) <= 64 else pl[:64].hex() + "..."))
    elif r["xfer"] == 2:
        print("%9.3f #%-6d %s %s stage=%s ep%02x st=%08x %s" % (
            r["ts"] - t0, r["n"], kind, "rsp" if r["resp"] else "req", r["stage"], r["ep"], r["status"], pl.hex()))
    else:
        print("%9.3f #%-6d %s %s ep%02x %s" % (r["ts"] - t0, r["n"], kind, "rsp" if r["resp"] else "req", r["ep"], pl.hex()))
