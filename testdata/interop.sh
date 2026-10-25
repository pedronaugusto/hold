#!/bin/sh
# The rivals read what hold writes: run by hand from the repository's root
# after `bay interop-write` has built the writer. For each dialect, the
# manifest libarchive 3.8.10 reads must be the one hold wrote, and GNU tar,
# Python's tarfile, Go's archive/tar and 7-Zip must list and extract it.
set -eu
# Manifests compared with names in NFC: libarchive's macOS build gives NFD.
same() { python3 -c "import sys,unicodedata as u; a,b=(u.normalize('NFC',open(p,encoding='utf-8').read()) for p in sys.argv[1:]); sys.exit(a!=b)" "$1" "$2"; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
P=$(brew --prefix libarchive)
cc -O2 -I"$P/include" testdata/tools/manifest.c -L"$P/lib" -larchive -o "$work/manifest"
zig-out/bin/interop-write "$work/out" > "$work/expected"
fail=0
for t in ustar pax gnu; do
  a="$work/out/$t.tar"
  awk -v n="== $t.tar" '$0==n{on=1;next} /^== /{on=0} on' "$work/expected" > "$work/want"
  "$work/manifest" "$a" > "$work/got"
  if same "$work/want" "$work/got"; then echo "libarchive $t: same entries"; else echo "libarchive $t: DIFFERS"; diff "$work/want" "$work/got" || true; fail=1; fi
  mkdir -p "$work/x/$t-gtar" "$work/x/$t-py"
  gtar -xf "$a" -C "$work/x/$t-gtar" && echo "gtar $t: extracted" || { echo "gtar $t: FAILED"; fail=1; }
  python3 -c "import tarfile,sys; tarfile.open(sys.argv[1]).extractall(sys.argv[2], filter='tar')" "$a" "$work/x/$t-py" && echo "python $t: extracted" || { echo "python $t: FAILED"; fail=1; }
  diff -r "$work/x/$t-gtar" "$work/x/$t-py" > /dev/null && echo "gtar and python $t: same tree" || { echo "gtar and python $t: trees differ"; fail=1; }
  7zz t "$a" > /dev/null && echo "7zz $t: tested" || { echo "7zz $t: FAILED"; fail=1; }
  cat > "$work/r.go" <<'GO'
package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
)

func main() {
	f, _ := os.Open(os.Args[1])
	r := tar.NewReader(f)
	n := 0
	for {
		_, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		io.Copy(io.Discard, r)
		n++
	}
	fmt.Println(n, "entries")
}
GO
  printf "go $t: " && go run "$work/r.go" "$a" || fail=1
done
for t in deflate stored zstd streamed zip64; do
  a="$work/out/$t.zip"
  awk -v n="== $t.zip" '$0==n{on=1;next} /^== /{on=0} on' "$work/expected" > "$work/want"
  TZ=UTC "$work/manifest" "$a" > "$work/got"
  if same "$work/want" "$work/got"; then echo "libarchive $t.zip: same entries"; else echo "libarchive $t.zip: DIFFERS"; diff "$work/want" "$work/got" || true; fail=1; fi
  if [ $t != zstd ]; then
    unzip -tq "$a" > /dev/null && echo "unzip $t.zip: tested" || { echo "unzip $t.zip: FAILED"; fail=1; }
    python3 -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None" "$a" && echo "python $t.zip: tested" || { echo "python $t.zip: FAILED"; fail=1; }
    cat > "$work/z.go" <<'GO'
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
)

func main() {
	r, err := zip.OpenReader(os.Args[1])
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			fmt.Println("error", f.Name, err)
			os.Exit(1)
		}
		rc.Close()
	}
	fmt.Println(len(r.File), "entries")
}
GO
    printf "go $t.zip: " && go run "$work/z.go" "$a" || fail=1
  fi
  7zz t "$a" > /dev/null && echo "7zz $t.zip: tested" || { echo "7zz $t.zip: FAILED"; fail=1; }
done
exit $fail
