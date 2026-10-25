#!/bin/sh
# hold's benchmark rows beside libarchive's and Go's, over the same files:
# hold-bench writes the trees, bsdtar and 7-Zip archive them, and each
# harness reads those archives and writes the trees to memory. Prints a
# Markdown table of medians. Run from the repository's root:
#   bay dev bench-build -p <prefix>
#   bench/rivals.sh <work dir> <prefix>/bench/hold-bench
# Tools: Homebrew libarchive (bsdtar 3.8 and the library), 7zz, go, python3.
set -eu
work=$1
hold_bench=$2
root=$(pwd)
lib=$(brew --prefix libarchive)
rm -rf "$work"
mkdir -p "$work"
"$hold_bench" --emit "$work"
for t in tree large; do
  (
    cd "$work/$t"
    top=$(ls)
    COPYFILE_DISABLE=1 "$lib/bin/bsdtar" --format ustar -cf "../$t.tar" $top
    COPYFILE_DISABLE=1 "$lib/bin/bsdtar" --format zip --options zip:compression-level=6 -cf "../$t-deflate.zip" $top
    COPYFILE_DISABLE=1 "$lib/bin/bsdtar" --format zip --options zip:compression=store -cf "../$t-store.zip" $top
    7zz a -mhc=off -m0=Deflate "../$t-deflate.7z" $top > /dev/null
  )
done
cc -O2 -I"$lib/include" "$root/bench/rivals/libarchive.c" -L"$lib/lib" -larchive -o "$work/libarchive-bench"
"$hold_bench" --corpus "$work" > "$work/hold.jsonl"
"$work/libarchive-bench" "$work" > "$work/libarchive.txt"
go run "$root/bench/rivals/go/main.go" "$work" > "$work/go.txt"
python3 - "$work" <<'PY'
import json, sys, os
work = sys.argv[1]
hold = {}
for line in open(os.path.join(work, "hold.jsonl")):
    r = json.loads(line)
    hold[r["row"]] = r["median"]
def plain(name):
    out = {}
    for line in open(os.path.join(work, name)):
        row, ns = line.split()
        out[row] = float(ns)
    return out
la, go = plain("libarchive.txt"), plain("go.txt")
sizes = {}
for t in ("tree", "large"):
    total = 0
    for d, _, files in os.walk(os.path.join(work, t)):
        for f in files:
            total += os.path.getsize(os.path.join(d, f))
    sizes[t] = total
print("| Row | hold | libarchive 3.8 | Go | hold MB/s |")
print("|---|---:|---:|---:|---:|")
for row, ns in hold.items():
    t = row.rsplit("/", 1)[1]
    cell = lambda v: f"{v / 1e6:.2f} ms" if v is not None else "—"
    print(f"| {row} | {cell(ns)} | {cell(la.get(row))} | {cell(go.get(row))} | {sizes[t] / ns * 1e3:.0f} |")
PY
