#!/bin/sh
# Build a .deb by staging `make install` into a temp root, then dpkg-deb.
set -e
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ver=$(sed -n 's/^Version: //p' "$here/control")

stage=$(mktemp -d)
make -C "$root" install DESTDIR="$stage" PREFIX=/usr
mkdir -p "$stage/DEBIAN"
cp "$here/control" "$stage/DEBIAN/control"

out="$root/ssh-socks-tray_${ver}_all.deb"
dpkg-deb --build --root-owner-group "$stage" "$out"
rm -rf "$stage"
echo "built $out"
