package certificate

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
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

	fmt.Printf("badssl.com.der.cert: \n%s\n", hex.Dump(c.EncodedCert))

	return

	/*
		if err := cert.Store("user", "ROOT"); err != nil {
			t.Fatal(err)
			return
		}
	*/
}
