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

# zip: the same kind of tree, by each zip writer.
zout=$(dirname "$out")/zip
mkdir -p "$zout"
rm -f "$zout"/*.zip
z=$work/ztree
mkdir -p "$z/dir"
printf 'hello\n' > "$z/dir/a.txt"
python3 -c "print('text line\n'*5000, end='')" > "$z/text.txt"
python3 -c "import random; random.seed(7); open('$z/rand.bin','wb').write(bytes(random.getrandbits(8) for _ in range(50000)))"
printf 'unicode\n' > "$z/dé.txt"
ln -s dir/a.txt "$z/link"
touch -h -t 202001020304.05 "$z/dir" "$z/dir/a.txt" "$z/text.txt" "$z/rand.bin" "$z/dé.txt" "$z/link"
cd "$z"
zfiles="dir dir/a.txt text.txt rand.bin dé.txt link"
zip -q -X -y "$zout/infozip-deflate.zip" $zfiles
zip -q -X -y -0 "$zout/infozip-store.zip" $zfiles
zip -q -X -y -fz "$zout/infozip-zip64.zip" $zfiles
cat text.txt | zip -q -X > "$zout/infozip-stdin.zip"
COPYFILE_DISABLE=1 bsdtar --format zip -cf "$zout/bsdtar-deflate.zip" $zfiles
COPYFILE_DISABLE=1 bsdtar --format zip --options zip:compression=store -cf "$zout/bsdtar-store.zip" $zfiles
for c in zstd bzip2 lzma xz; do
  COPYFILE_DISABLE=1 "$(brew --prefix libarchive)/bin/bsdtar" --format zip --options zip:compression=$c -cf "$zout/bsdtar38-$c.zip" $zfiles
done
python3 - "$zout" <<'PY'
import sys, zipfile, os
out = sys.argv[1]
for name, method in (("deflate", zipfile.ZIP_DEFLATED), ("store", zipfile.ZIP_STORED), ("bzip2", zipfile.ZIP_BZIP2), ("lzma", zipfile.ZIP_LZMA)):
    with zipfile.ZipFile(os.path.join(out, f"python-{name}.zip"), "w", method) as zf:
        for f in ["dir", "dir/a.txt", "text.txt", "rand.bin", "dé.txt"]:
            zf.write(f)
PY
cat > "$work/gozip.go" <<'GO'
package main

import (
	"archive/zip"
	"io"
	"os"
)

func main() {
	f, _ := os.Create(os.Args[1])
	w := zip.NewWriter(f)
	for _, name := range []string{"dir/a.txt", "text.txt", "rand.bin", "dé.txt"} {
		info, _ := os.Stat(name)
		h, _ := zip.FileInfoHeader(info)
		h.Name = name
		h.Method = zip.Deflate
		out, _ := w.CreateHeader(h)
		in, _ := os.Open(name)
		io.Copy(out, in)
		in.Close()
	}
	w.SetComment("go comment")
	w.Close()
	f.Close()
}
GO
go run "$work/gozip.go" "$zout/go-deflate.zip"
7zz a -tzip -snl "$zout/7zz-deflate.zip" $zfiles > /dev/null
7zz a -tzip -snl -mm=Deflate64 "$zout/7zz-deflate64.zip" $zfiles > /dev/null
7zz a -tzip -snl -mm=BZip2 "$zout/7zz-bzip2.zip" $zfiles > /dev/null
7zz a -tzip -snl -phold -mem=AES256 "$zout/7zz-aes256.zip" $zfiles > /dev/null
7zz a -tzip -snl -phold -mem=AES128 "$zout/7zz-aes128.zip" $zfiles > /dev/null
7zz a -tzip -snl -phold -mem=AES192 "$zout/7zz-aes192.zip" $zfiles > /dev/null
7zz a -tzip -snl -phold -mem=ZipCrypto "$zout/7zz-zipcrypto.zip" $zfiles > /dev/null

# 7z: the same tree by 7-Zip, uncompressed headers so the coders warp has
# are what decides; and by bsdtar 3.8's 7z writer.
sout=$(dirname "$out")/sevenz
mkdir -p "$sout"
rm -f "$sout"/*.7z
7zz a -snl -mhc=off -m0=Copy "$sout/7zz-copy.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -m0=Deflate "$sout/7zz-deflate.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -m0=Deflate -ms=off "$sout/7zz-deflate-nonsolid.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -m0=Deflate -mtc=on -mta=on "$sout/7zz-deflate-times.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -m0=Deflate64 "$sout/7zz-deflate64.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -m0=BZip2 "$sout/7zz-bzip2.7z" $zfiles > /dev/null
7zz a -snl "$sout/7zz-lzma2.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -mf=BCJ -m0=Deflate "$sout/7zz-bcj-deflate.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -phold -m0=Copy "$sout/7zz-aes-copy.7z" $zfiles > /dev/null
7zz a -snl -mhc=off -phold -m0=Deflate "$sout/7zz-aes-deflate.7z" $zfiles > /dev/null
7zz a -snl -phold -mhe=on "$sout/7zz-aes-header.7z" $zfiles > /dev/null
for c in store deflate bzip2 lzma1 lzma2 ppmd zstd; do
  COPYFILE_DISABLE=1 "$(brew --prefix libarchive)/bin/bsdtar" --format 7zip --options 7zip:compression=$c -cf "$sout/bsdtar38-$c.7z" $zfiles
done
cd - > /dev/null

# The manifests libarchive reads from each archive, here and in the
# libarchive corpus (decoded from its test/*.uu by hand).
P=$(brew --prefix libarchive)
cc -O2 -I"$P/include" "$(dirname "$out")/tools/manifest.c" -L"$P/lib" -larchive -o "$work/manifest"
for f in "$out"/*.tar "$(dirname "$out")"/libarchive/*.tar "$zout"/*.zip "$(dirname "$out")"/libarchive/*.zip "$(dirname "$out")"/libarchive/*.zipx "$sout"/*.7z "$(dirname "$out")"/libarchive/*.7z; do
  if [ -f "$f" ]; then TZ=UTC "$work/manifest" "$f" > "$f.manifest"; fi
done
