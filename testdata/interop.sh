#!/bin/sh
# The rivals read what hold writes: run by hand from the repository's root
# after `bay interop-write` has built the writer. For each dialect, the
# manifest libarchive 3.8.10 reads must be the one hold wrote, and GNU tar,
# Python's tarfile, Go's archive/tar and 7-Zip must list and extract it.
set -eu
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
  if cmp -s "$work/want" "$work/got"; then echo "libarchive $t: same entries"; else echo "libarchive $t: DIFFERS"; diff "$work/want" "$work/got" || true; fail=1; fi
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
exit $fail
