package cli

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tarBlock is one 512-byte ustar header.
func tarBlock(name string, typ byte, size int) []byte {
	b := make([]byte, 512)
	copy(b, name)
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	copy(b[136:], "00000000000\x00")
	copy(b[148:], "        ")
	b[156] = typ
	copy(b[257:], "ustar\x0000")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func pad512(b []byte) []byte {
	if r := len(b) % 512; r != 0 {
		b = append(b, make([]byte, 512-r)...)
	}
	return b
}

// sparseTar is a tar of a few blocks whose one file (PAX GNU sparse 1.0)
// unpacks to real bytes.
func sparseTar(name string, real int) []byte {
	rec := func(k, v string) string {
		n := len(k) + len(v) + 3
		for len(fmt.Sprint(n))+n != len(fmt.Sprintf("%d %s=%s\n", len(fmt.Sprint(n))+n, k, v)) {
			n++
		}
		return fmt.Sprintf("%d %s=%s\n", len(fmt.Sprint(n))+n, k, v)
	}
	pax := rec("GNU.sparse.major", "1") + rec("GNU.sparse.minor", "0") + rec("GNU.sparse.name", name) + rec("GNU.sparse.realsize", fmt.Sprint(real))
	// the map: one data piece, 1 byte long, at the very end
	body := pad512([]byte(fmt.Sprintf("1\n%d\n1\n", real-1)))
	body = append(body, 'x')
	var b bytes.Buffer
	b.Write(tarBlock("PaxHeaders/"+name, 'x', len(pax)))
	b.Write(pad512([]byte(pax)))
	b.Write(tarBlock("GNUSparseFile.0/"+name, '0', len(body)))
	b.Write(pad512(body))
	b.Write(make([]byte, 1024))
	return b.Bytes()
}

// A pod picks the sizes in the tar it sends: a sparse entry of a few
// blocks must not unpack to a huge file on this computer.
func TestClusterCpSparseEntry(t *testing.T) {
	tb := sparseTar("big.bin", 64<<20)
	// the fixture is what it claims: Go's reader unpacks it to 64 MiB
	tr := tar.NewReader(bytes.NewReader(tb))
	h, err := tr.Next()
	if err != nil || h.Name != "big.bin" || h.Size != 64<<20 {
		t.Fatalf("fixture: %+v %v", h, err)
	}
	if len(tb) > 8<<10 {
		t.Fatalf("fixture is %d bytes", len(tb))
	}
	dst := filepath.Join(t.TempDir(), "out")
	os.MkdirAll(dst, 0o755)
	err = untarTo(tcl, tb, dst, "big.bin")
	if err == nil || !strings.Contains(err.Error(), "sparse") {
		t.Errorf("want the sparse entry refused, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dst, "big.bin")); serr == nil {
		t.Error("the sparse file was written")
	}
}
