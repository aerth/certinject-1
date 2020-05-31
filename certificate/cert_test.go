package certificate

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestDeSerializeFromFile(t *testing.T) {
	type testcase struct {
		Filename string
		Err      error
	}
	hash1 := "99c1daf07c8d69a8a065492dcaae43c43ff13497"
	for _, tc := range []testcase{
		{"../testdata/badssl.com.der.cert", nil},
		{"../testdata/1de4074b4e38377f4367303f4a19c986a506180f22a6e53a68cc7679ea6d9c74.pem", nil},
	} {
		buf, err := ioutil.ReadFile(tc.Filename)
		if err != nil {
			t.Error(err)
			t.FailNow()
			return
		}
		cert2, err := FromBytes(buf)
		if err != tc.Err {
			t.Errorf("Wanted: %v, Got: %v", tc.Err, err)
			t.FailNow()
			return
		}
		cert, err := FromFile(tc.Filename)
		if err != tc.Err {
			t.Errorf("Wanted: %v, Got: %v", tc.Err, err)
			t.FailNow()
			return
		}
		if tc.Err != nil {
			return
		}
		if bytes.Compare(cert.Raw, cert2.Raw) != 0 {
			t.Errorf("cert1 != cert 2")
			t.FailNow()

		}
		if cert == nil {
			t.Errorf("Wanted: non-nil, Got: %v", cert)
			t.FailNow()
			return
		}
		hash2 := fmt.Sprintf("%02x", cert.Sha1())
		hash3 := cert.FingerprintHex()
		if hash1 != hash2 || hash3 != hash2 {
			t.Errorf("Wanted: %s, Got: %s", hash1, hash2)
			t.FailNow()
		}
		t.Logf("%-.6s...: %s\n", filepath.Base(tc.Filename), cert.String())
		//		fmt.Fprintf(os.Stderr, "PEM:\n%s\n", string(cert.ToPEM()))
	}
	return
}

func TestFingerprintStrings(t *testing.T) {
	for _, tc := range []struct {
		Filename string
		Err      error
	}{{"../testdata/badssl.com.der.cert", nil}} {

		cert, err := FromFile(tc.Filename)
		if err != nil {
			t.Fatal(err)
			return
		}
		fmt.Println("Fingerprint1:", cert.FingerprintHex())
		fmt.Println("Fingerprint2:", cert.FingerprintColons())
	}
}
