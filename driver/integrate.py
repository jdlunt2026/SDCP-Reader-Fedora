#!/usr/bin/env python3
"""Add the realtek_sdcp driver to a libfprint (>= 1.95, with SDCP) source tree.

Usage: python3 -I integrate.py /path/to/libfprint-source
"""
import pathlib
import shutil
import sys

DRIVER = "realtek_sdcp"
here = pathlib.Path(__file__).resolve().parent
src = pathlib.Path(sys.argv[1]).resolve()


def patch(path, anchor, insert, after=True, marker=DRIVER):
    text = path.read_text()
    if f"'{marker}'" in text:
        return  # already integrated
    if text.count(anchor) != 1:
        sys.exit(f"{path}: anchor not found exactly once: {anchor!r}")
    new = anchor + insert if after else insert + anchor
    path.write_text(text.replace(anchor, new))


if not (src / "libfprint" / "fpi-sdcp-device.c").exists():
    sys.exit(f"{src} has no SDCP support (libfprint/fpi-sdcp-device.c missing)")

shutil.copytree(here / "realtek-sdcp", src / "libfprint" / "drivers" / "realtek-sdcp",
                dirs_exist_ok=True)

# libfprint/meson.build: driver source file
patch(src / "libfprint" / "meson.build",
      "    'realtek': files('drivers/realtek/realtek.c'),\n",
      "    'realtek_sdcp': files('drivers/realtek-sdcp/realtek-sdcp.c'),\n")

# meson.build: enable by default and pull in the SDCP helper (OpenSSL)
top = src / "meson.build"
text = top.read_text()
if f"'{DRIVER}'" not in text:
    for anchor, insert in (
        ("    'realtek',\n", f"    '{DRIVER}',\n"),  # default_drivers (first occurrence)
        ("    'virtual_sdcp'           : [ 'virtual', 'sdcp' ],\n",
         f"    '{DRIVER}'           : [ 'sdcp' ],\n"),
    ):
        if anchor not in text:
            sys.exit(f"{top}: anchor not found: {anchor!r}")
        text = text.replace(anchor, anchor + insert, 1)
    top.write_text(text)

# The libfprint-tod tree calls the TOD loader unconditionally, so building with
# -Dtod=false fails to link. Guard those calls (no-op if already fixed).
ctx = src / "libfprint" / "fp-context.c"
text = ctx.read_text()
fixes = (
    ("#ifdef HAVE_LIBFPRINT_TOD\n", "#if HAVE_LIBFPRINT_TOD\n"),
    ("\n  tod_shared_drivers_unregister ();\n",
     "\n#if HAVE_LIBFPRINT_TOD\n  tod_shared_drivers_unregister ();\n#endif\n"),
    ("  tod_shared_drivers_register ();\n"
     "  shared_drivers = tod_shared_drivers_get ();\n"
     "  g_array_prepend_vals (priv->drivers, shared_drivers->data, shared_drivers->len);\n",
     "#if HAVE_LIBFPRINT_TOD\n"
     "  tod_shared_drivers_register ();\n"
     "  shared_drivers = tod_shared_drivers_get ();\n"
     "  g_array_prepend_vals (priv->drivers, shared_drivers->data, shared_drivers->len);\n"
     "#endif\n"),
)
if "tod_shared_drivers_get" in text and "#if HAVE_LIBFPRINT_TOD\n  tod_shared_drivers_register" not in text:
    for old, new in fixes:
        if text.count(old) != 1:
            sys.exit(f"{ctx}: TOD guard anchor not found: {old!r}")
        text = text.replace(old, new)
    text = text.replace("  g_autoptr(GArray) shared_drivers = NULL;\n",
                        "#if HAVE_LIBFPRINT_TOD\n  g_autoptr(GArray) shared_drivers = NULL;\n#endif\n", 1)
    ctx.write_text(text)

# fpi_sdcp_kdf() passes the two KDF context parts as two OSSL_KDF_PARAM_INFO
# parameters. OpenSSL 3.0.x keeps only the first one (newer releases
# concatenate them), which breaks SDCP key derivation there. Pass a single,
# pre-concatenated context instead: identical result on every OpenSSL.
sdcp = src / "libfprint" / "fpi-sdcp.c"
text = sdcp.read_text()
old_info = """  if (context_a)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     (void *) (g_bytes_get_data (context_a, NULL)),
                                                     g_bytes_get_size (context_a));

  if (context_b)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     (void *) (g_bytes_get_data (context_b, NULL)),
                                                     g_bytes_get_size (context_b));
"""
new_info = """  g_autoptr(GByteArray) context = g_byte_array_new ();

  if (context_a)
    g_byte_array_append (context, g_bytes_get_data (context_a, NULL), g_bytes_get_size (context_a));
  if (context_b)
    g_byte_array_append (context, g_bytes_get_data (context_b, NULL), g_bytes_get_size (context_b));

  if (context->len > 0)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     context->data, context->len);
"""
if new_info not in text:
    if text.count(old_info) != 1:
        sys.exit(f"{sdcp}: KDF context anchor not found")
    sdcp.write_text(text.replace(old_info, new_info))

print(f"{DRIVER} integrated into {src}")
