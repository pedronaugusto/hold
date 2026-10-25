#!/bin/sh
# Writes the interop corpus: the same tree archived by each rival's own
# tool. Run by hand from the repository's root; the archives are committed.
# Tools: bsdtar (libarchive), gtar (GNU tar 1.35), go, python3, 7zz.
set -eu
out=$(pwd)/testdata/tar
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tree=$work/tree
mkdir -p "$tree/dir/sub"
printf 'hello\n' > "$tree/dir/a.txt"
: > "$tree/empty"
printf '#!/bin/sh\necho x\n' > "$tree/run.sh"; chmod 755 "$tree/run.sh"
long=$(printf 'x%.0s' $(seq 1 120))
mkdir -p "$tree/dir/$long"
printf 'long\n' > "$tree/dir/$long/$(printf 'y%.0s' $(seq 1 110)).txt"
printf 'unicode\n' > "$tree/dé.txt"
ln -s dir/a.txt "$tree/link"
ln "$tree/dir/a.txt" "$tree/hard"
cd "$tree"
files="dir empty run.sh dé.txt link hard"
touch -h -t 202001020304.05 $files dir/a.txt dir/sub "dir/$long" "dir/$long"/*
for f in ustar pax gnu oldgnu v7 posix; do
  [ $f = v7 ] && sel="dir empty run.sh link hard" || sel=$files
  gtar --format=$f --owner=0 --group=0 --numeric-owner -cf "$out/gtar-$f.tar" $sel 2>/dev/null || true
done
# Sparse archives come from libarchive's corpus: macOS's APFS keeps no
# holes for GNU tar to find, so a sparse file made here is stored whole.
for f in ustar pax gnutar v7tar; do
  COPYFILE_DISABLE=1 bsdtar --no-mac-metadata --format=$f --uid 0 --gid 0 -cf "$out/bsdtar-$f.tar" $files 2>/dev/null || true
done
python3 - "$out" <<'PY'
import sys, tarfile, os
out = sys.argv[1]
for name, fmt in (("pax", tarfile.PAX_FORMAT), ("gnu", tarfile.GNU_FORMAT)):
    with tarfile.open(os.path.join(out, f"python-{name}.tar"), "w", format=fmt) as t:
        for f in ["dir", "empty", "run.sh", "dé.txt", "link", "hard"]:
            t.add(f)
PY
cat > "$work/gotar.go" <<'GO'
package main

import (
	"archive/tar"
	"os"
	"path/filepath"
)

func main() {
	f, _ := os.Create(os.Args[1])
	w := tar.NewWriter(f)
	filepath.Walk(".", func(p string, info os.FileInfo, err error) error {
		if p == "." {
			return nil
		}
		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			link, _ = os.Readlink(p)
		}
		h, _ := tar.FileInfoHeader(info, link)
		h.Name = p
		h.Format = tar.FormatPAX
		w.WriteHeader(h)
		if info.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			w.Write(b)
		}
		return nil
	})
	w.Close()
	f.Close()
}
GO
go run "$work/gotar.go" "$out/go-pax.tar"
7zz a -ttar -snl "$out/7zz.tar" $files > /dev/null
ls -l "$out"
# The manifests libarchive reads from each archive, here and in the
# libarchive corpus (decoded from its test/*.uu by hand).
P=$(brew --prefix libarchive)
cc -O2 -I"$P/include" "$(dirname "$out")/tools/manifest.c" -L"$P/lib" -larchive -o "$work/manifest"
for f in "$out"/*.tar "$(dirname "$out")"/libarchive/*.tar; do "$work/manifest" "$f" > "$f.manifest"; done
