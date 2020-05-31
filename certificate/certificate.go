package certificate

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"crypto/sha1"
	"crypto/x509"
)

type Certificate x509.Certificate

func (c Certificate) String() string {
	return fmt.Sprintf("CERTIFICATE(%s)", c.FingerprintHex())
}

func (c Certificate) FingerprintHex() string {
	return fmt.Sprintf("%02x", c.Sha1())
}
func (c Certificate) FingerprintColons() string {
	return strings.Replace(fmt.Sprintf("% 02x", c.Sha1()), " ", ":", -1)
}

func (c Certificate) Sha1() []byte {
	hash := sha1.Sum(c.Raw)
	return hash[:]
}

func FromFile(name string) (*Certificate, error) {
	if name == "" {
		return nil, os.ErrInvalid
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	var (
		buf = new(bytes.Buffer)
	)

	_, err = io.Copy(buf, f)
	if errc := f.Close(); errc != nil {
		println("error closing file:", errc.Error())
	}
	if err != nil {
		println("error reading file")
		return nil, err
	}
	return FromBytes(buf.Bytes())
}

func FromBytes(buf []byte) (*Certificate, error) {
	// maybe is pem encoded
	if err := func() error {
		block, _ := pem.Decode(buf)
		if block != nil {
			if block.Type != "CERTIFICATE" {
				return os.ErrInvalid
			}
			buf = block.Bytes // get the DER
		}
		return nil
	}(); err != nil {
		return nil, err
	}

	// parse x509 cert from buffer (ASN.1 DER)
	c, err := x509.ParseCertificate(buf)
	if err != nil {
		println("error reading certificate")
		return nil, err
	}

	// wrap
	var cert = new(Certificate)
	*cert = Certificate(*c)
	return cert, nil

}

func pemEncode(t string, b []byte) []byte {
	block := &pem.Block{
		Type:  t,
		Bytes: b,
	}
	return pem.EncodeToMemory(block)
}
func (c Certificate) ToPEM() []byte {
	return pemEncode("CERTIFICATE", c.Raw)
}
