// Go's side of hold's benchmark rows: archive/tar and archive/zip over the
// same trees (written by `hold-bench --emit`) and the same archives
// (bench/rivals.sh). Prints one line a row: "<row> <median ns per archive>".
//
//	go run ./bench/rivals/go <corpus dir>
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type tree struct {
	name  string
	names []string
	data  [][]byte
	total int
}

func load(dir, which string) tree {
	t := tree{name: which}
	if which == "large" {
		t.names = []string{"large/text.txt", "large/random.bin"}
	} else {
		for n := 0; n < 2000; n++ {
			t.names = append(t.names, fmt.Sprintf("src/d%d/f%d.txt", n%40, n))
		}
	}
	for _, n := range t.names {
		b, err := os.ReadFile(filepath.Join(dir, which, n))
		if err != nil {
			panic(err)
		}
		t.data = append(t.data, b)
		t.total += len(b)
	}
	return t
}

var scratch = make([]byte, 64*1024)

func readTar(b []byte, want int) {
	r := tar.NewReader(bytes.NewReader(b))
	total := 0
	for {
		_, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		n, err := io.CopyBuffer(io.Discard, struct{ io.Reader }{r}, scratch)
		if err != nil {
			panic(err)
		}
		total += int(n)
	}
	if total != want {
		panic("short tar")
	}
}

func readZip(b []byte, want int) {
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		panic(err)
	}
	total := 0
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			panic(err)
		}
		n, err := io.CopyBuffer(io.Discard, struct{ io.Reader }{rc}, scratch)
		if err != nil {
			panic(err)
		}
		rc.Close()
		total += int(n)
	}
	if total != want {
		panic("short zip")
	}
}

func writeTar(t tree, out *bytes.Buffer) {
	out.Reset()
	w := tar.NewWriter(out)
	for i, n := range t.names {
		w.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(t.data[i])), Typeflag: tar.TypeReg})
		w.Write(t.data[i])
	}
	w.Close()
}

func writeZip(t tree, out *bytes.Buffer, method uint16) {
	out.Reset()
	w := zip.NewWriter(out)
	w.RegisterCompressor(zip.Deflate, func(o io.Writer) (io.WriteCloser, error) { return flate.NewWriter(o, 6) })
	for i, n := range t.names {
		f, _ := w.CreateHeader(&zip.FileHeader{Name: n, Method: method})
		f.Write(t.data[i])
	}
	w.Close()
}

// Eleven samples of at least 10 ms each, after two warmups: the median ns
// per archive.
func row(name string, t tree, fn func()) {
	fn()
	fn()
	s := make([]float64, 11)
	for i := range s {
		start := time.Now()
		units := 0
		for time.Since(start) < 10*time.Millisecond {
			fn()
			units++
		}
		s[i] = float64(time.Since(start).Nanoseconds()) / float64(units)
	}
	sort.Float64s(s)
	fmt.Printf("%s/%s %.0f\n", name, t.name, s[len(s)/2])
}

func main() {
	dir := os.Args[1]
	for _, which := range []string{"tree", "large"} {
		t := load(dir, which)
		read := func(suffix string) []byte {
			b, err := os.ReadFile(filepath.Join(dir, which+suffix))
			if err != nil {
				panic(err)
			}
			return b
		}
		tarBytes, zipBytes, storeBytes := read(".tar"), read("-deflate.zip"), read("-store.zip")
		var out bytes.Buffer
		out.Grow(t.total + t.total/4 + 1<<20)
		row("tar/read", t, func() { readTar(tarBytes, t.total) })
		row("tar/write", t, func() { writeTar(t, &out) })
		row("zip/read-deflate", t, func() { readZip(zipBytes, t.total) })
		row("zip/read-store", t, func() { readZip(storeBytes, t.total) })
		row("zip/write-deflate", t, func() { writeZip(t, &out, zip.Deflate) })
		row("zip/write-store", t, func() { writeZip(t, &out, zip.Store) })
	}
}
