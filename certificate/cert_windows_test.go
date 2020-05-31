package certificate

import (
	"fmt"
	"os"
	"testing"
	"strings"
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

	fmt.Println("trying to store alternate way")
	if err := cert.Store("user", "ROOT"); err != nil {
		t.Fatal(err)
		return
	}
}
