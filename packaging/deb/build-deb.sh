#!/bin/sh
# Build a .deb by staging `make install` into a temp root, then dpkg-deb.
# Version comes from pyproject.toml (single source of truth).
set -e
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/pyproject.toml")
[ -n "$ver" ] || { echo "could not read version from pyproject.toml" >&2; exit 1; }

stage=$(mktemp -d)
make -C "$root" install DESTDIR="$stage" PREFIX=/usr
mkdir -p "$stage/DEBIAN"
sed "s/@VERSION@/$ver/" "$here/control" > "$stage/DEBIAN/control"

out="$root/tunly_${ver}_all.deb"
dpkg-deb --build --root-owner-group "$stage" "$out"
rm -rf "$stage"
echo "built $out"
