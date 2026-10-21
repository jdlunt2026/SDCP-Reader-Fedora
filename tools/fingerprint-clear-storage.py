#!/usr/bin/env python3
# List the fingerprints stored on the reader's chip, then (after confirmation)
# wipe the chip's template storage. This also removes any Windows Hello
# fingerprints stored on this reader.
#
# Run:  sudo systemctl stop fprintd
#       sudo G_MESSAGES_DEBUG=all python3 fingerprint-clear-storage.py 2>&1 | tee ~/fingerprint-clear.log

import functools
import gi
gi.require_version("FPrint", "2.0")

print = functools.partial(print, flush=True)  # show output immediately even when piped through tee
from gi.repository import FPrint, GLib


def list_prints(dev):
    try:
        prints = dev.list_prints_sync(None)
        print("Stored prints:", len(prints))
        for p in prints:
            fields = []
            for name, getter in (("user", p.get_username), ("desc", p.get_description)):
                try:
                    fields.append("%s=%r" % (name, getter()))
                except UnicodeDecodeError:
                    # Records written by Windows Hello aren't valid UTF-8
                    fields.append("%s=<binary, not written by Linux>" % name)
            print("  " + " ".join(fields))
    except GLib.Error as e:
        print("list_prints failed: code=%s message=%r" % (e.code, e.message))


ctx = FPrint.Context()
ctx.enumerate()
devs = ctx.get_devices()
if not devs:
    raise SystemExit("No fingerprint device found.")

dev = devs[0]
print("Device: driver=%s name=%s" % (dev.get_driver(), dev.get_name()))
dev.open_sync(None)
try:
    print("\n=== Before ===")
    list_prints(dev)

    print("\nWipe ALL fingerprints stored on this reader (including Windows Hello ones)?")
    answer = input("Type YES to wipe, anything else to skip: ")
    if answer.strip() == "YES":
        try:
            dev.clear_storage_sync(None)
            print("Storage cleared.")
        except GLib.Error as e:
            print("clear_storage failed: code=%s message=%r" % (e.code, e.message))
        print("\n=== After ===")
        list_prints(dev)
    else:
        print("Not cleared.")
finally:
    dev.close_sync(None)
