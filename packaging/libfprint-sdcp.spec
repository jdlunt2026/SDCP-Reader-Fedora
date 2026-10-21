# libfprint 1.95.2 (with SDCP support) plus the realtek_sdcp driver for the
# 2c0a:5816 Realtek "Secure BIO Sensor". Built by fedora-build.sh.

%global srcver   1.95.2+tod1
%global srcdir   libfprint-v%{srcver}

Name:           libfprint
Version:        1.95.2
Release:        0.rtksdcp1%{?dist}
Summary:        Toolkit for fingerprint scanner (with realtek_sdcp driver)

License:        LGPL-2.1-or-later
URL:            https://github.com/jdlunt2026/SDCP-Reader-Fedora
Source0:        libfprint_%{srcver}.orig.tar.bz2
Source1:        realtek-sdcp-driver.tar.gz

BuildRequires:  meson
BuildRequires:  gcc
BuildRequires:  python3
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(gusb)
BuildRequires:  pkgconfig(gudev-1.0)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(pixman-1)
BuildRequires:  pkgconfig(udev)
BuildRequires:  gobject-introspection-devel
BuildRequires:  systemd-rpm-macros

%description
libfprint 1.95.2 with Secure Device Connection Protocol (SDCP) support and the
realtek_sdcp driver for the Realtek 2c0a:5816 match-on-chip fingerprint reader.

%package devel
Summary:        Development package for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
Development files for libfprint.

%prep
%autosetup -n %{srcdir}
tar -xzf %{SOURCE1}
python3 -I driver/integrate.py .

%build
%meson -Ddoc=false -Dtod=false -Dinstalled-tests=false -Dgtk-examples=false
%meson_build

%install
%meson_install

%files
%license COPYING
%{_libdir}/libfprint-2.so.2*
%{_libdir}/girepository-1.0/FPrint-2.0.typelib
%{_udevrulesdir}/70-libfprint-2.rules
%{_datadir}/metainfo/org.freedesktop.libfprint.metainfo.xml

%files devel
%{_includedir}/libfprint-2/
%{_libdir}/libfprint-2.so
%{_libdir}/pkgconfig/libfprint-2.pc
%{_datadir}/gir-1.0/FPrint-2.0.gir

%changelog
* Wed Oct 21 2026 Jared Lunt <jdlunt2026@users.noreply.github.com> - 1.95.2-0.rtksdcp1
- libfprint 1.95.2 with the realtek_sdcp driver for USB 2c0a:5816
