package certificate

import (
	"fmt"
	"unicode/utf16"
	"unsafe"

	windows "golang.org/x/sys/windows"
)

// To Microsoft's "Certificate Registry Blob" format
// Format documentation of Microsoft's "Certificate Registry Blob":

// 5c 00 00 00 // propid
// 01 00 00 00 // unknown (possibly a version or flags field; value is always the same in my testing)
// 04 00 00 00 // size (little endian)
// subject public key bit length // data[size]

// 19 00 00 00
// 01 00 00 00
// 10 00 00 00
// MD5 of ECC pubkey of certificate

// 0f 00 00 00
// 01 00 00 00
// 20 00 00 00
// Signature Hash

// 03 00 00 00
// 01 00 00 00
// 14 00 00 00
// Cert SHA1 hash

// 14 00 00 00
// 01 00 00 00
// 14 00 00 00
// Key Identifier

// 04 00 00 00
// 01 00 00 00
// 10 00 00 00
// Cert MD5 hash

// 20 00 00 00
// 01 00 00 00
// cert length
// cert

// But, guess what?  All you need is the "20" record.
// Windows will happily regenerate all the others for you, whenever you actually try to use the certificate.
// How cool is that?
func (c Certificate) ToWindowsBlob() []byte {
	certLength := len(c.Raw)
	header := []byte{
		0:  0x20,
		4:  0x01,
		8:  byte((certLength >> 0) & 0xFF),
		9:  byte((certLength >> 8) & 0xFF),
		10: byte((certLength >> 16) & 0xFF),
		11: byte((certLength >> 24) & 0xFF),
	}
	return append(header, c.Raw...)
}

const (
	// constants from https://referencesource.microsoft.com/#System.Security/system/security/cryptography/cryptoapi.cs,211
	compareShift    = 16    // CERT_COMPARE_SHIFT
	encodingX509ASN = 1     // X509_ASN_ENCODING
	encodingPKCS7   = 65536 // PKCS_7_ASN_ENCODING

	capiProvPKCS7          = 5  // CERT_STORE_PROV_PKCS7
	capiProvSystem         = 10 // CERT_STORE_PROV_SYSTEM
	capiProvSystemRegistry = 13 // CERT_STORE_PROV_SYSTEM_REGISTRY

	capiCurrentUserID  = 1 // CERT_SYSTEM_STORE_CURRENT_USER_ID
	capiLocalMachineID = 2 // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID

	capiCurrentUser  = uint32(capiCurrentUserID << compareShift)  // CERT_SYSTEM_STORE_CURRENT_USER
	capiLocalMachine = uint32(capiLocalMachineID << compareShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE

)

func wide(s string) *uint16 {
	w := utf16.Encode([]rune(s))
	w = append(w, 0)
	return &w[0]
}

func (c Certificate) Store(physicalStoreName, logicalStoreName string) error {
	var physicalStore uint32 = capiCurrentUser
	var provider uintptr = capiProvSystem
	switch physicalStoreName {
	case "system":
		physicalStore = capiLocalMachine
	case "user":
		physicalStore = capiCurrentUser
	}
	logicalStore := wide(logicalStoreName)
	certContext, err := windows.CertCreateCertificateContext(
		encodingX509ASN|encodingPKCS7,
		&c.Raw[0],
		uint32(len(c.Raw)))
	if err != nil {
		return fmt.Errorf("error creating context: %v", err)
	}
	defer windows.CertFreeCertificateContext(certContext)
	userStore, err := windows.CertOpenStore(
		provider,
		0,
		0,
		physicalStore,
		uintptr(unsafe.Pointer(logicalStore)))
	if err != nil {
		return fmt.Errorf("error opening store: %v", err)
	}
	defer windows.CertCloseStore(userStore, 0)
	if err := windows.CertAddCertificateContextToStore(userStore, certContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("error adding certificate to store: %v", err)
	}
	return nil
}
