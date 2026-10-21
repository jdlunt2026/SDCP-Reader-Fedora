#!/usr/bin/python3

import traceback
import sys
import gi

gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib

# Exit with error on any exception, included those happening in async callbacks
sys.excepthook = lambda *args: (traceback.print_exception(*args), sys.exit(1))

ctx = GLib.main_context_default()

c = FPrint.Context()
c.enumerate()
devices = c.get_devices()

d = devices[0]
del devices

assert d.get_driver() == "realtek_sdcp"
assert not d.has_feature(FPrint.DeviceFeature.CAPTURE)
assert d.has_feature(FPrint.DeviceFeature.IDENTIFY)
assert d.has_feature(FPrint.DeviceFeature.VERIFY)
assert d.has_feature(FPrint.DeviceFeature.DUPLICATES_CHECK)
assert d.has_feature(FPrint.DeviceFeature.STORAGE)
assert d.has_feature(FPrint.DeviceFeature.STORAGE_LIST)
assert d.has_feature(FPrint.DeviceFeature.STORAGE_DELETE)
assert d.has_feature(FPrint.DeviceFeature.STORAGE_CLEAR)
assert d.get_nr_enroll_stages() == 12

# Open runs the SDCP connect handshake (claim + MAC verification)
d.open_sync()

d.clear_storage_sync()

template = FPrint.Print.new(d)
progress = []


def enroll_progress(dev, stage, print_, user_data, error):
    progress.append((stage, error.message if error else None))
    print('enroll progress: stage %d %s' % (stage, error.message if error else ''))


print("enrolling")
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
p = d.enroll_sync(template, None, enroll_progress, None)
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
print("enroll done")
assert [s for s, e in progress if e is None] == list(range(1, 13))
assert len([e for s, e in progress if e is not None]) == 1   # the one rejected sample
assert p.get_device_stored()

print("listing")
stored = d.list_prints_sync()
assert len(stored) == 1   # ids listed are SHA256(id), as stored on the chip

print("verifying")
verify_res, verify_print = d.verify_sync(p)
assert verify_res
assert verify_print.equal(p)
print("verify done")

print("identifying")
deserialized = FPrint.Print.deserialize(p.serialize())
assert deserialized.equal(p)
match, found = d.identify_sync([deserialized])
assert match is not None and match.equal(p)
print("identify done")

print("deleting")
d.delete_print_sync(p)
print("delete done")

d.close_sync()

del d
del c
