package certificate

import (
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestWindows(t *testing.T) {
	cert, err := FromFile("../testdata/badssl.com.der.cert")
	if err != nil {
		t.Fatal(err)
		return
	}
	fmt.Println(strings.ToUpper(cert.FingerprintHex()))
	b := cert.ToWindowsBlob()
	fmt.Fprintf(os.Stderr, "Blob: %02X\n", b)

	c, err := cert.ToContext()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer cert.FreeContext(c)

	var tmp []byte
	p := (*reflect.SliceHeader)(unsafe.Pointer(&tmp))
	p.Data = uintptr(unsafe.Pointer(c.EncodedCert))
	p.Len = int(c.Length)
	p.Cap = int(c.Length)

	var buf = make([]byte, c.Length)
	copy(buf, tmp)

	fmt.Printf("badssl.com.der.cert: \n%s\n", hex.Dump(buf))

	return

	/*
		if err := cert.Store("user", "ROOT"); err != nil {
			t.Fatal(err)
			return
		}
	*/
}
