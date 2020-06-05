// +build !windows

package certinject

import "fmt"

// This package is used to add and remove certificates to the system trust
// store.
// Currently only supports NSS sqlite3 stores.

// InjectCert injects the given cert into all configured trust stores.
func InjectCert(derBytes []byte) error {
	if nssFlag.Value() {
		return injectCertNss(derBytes)
	}
	return fmt.Errorf("no store was selected")
}

// CleanCerts cleans expired certs from all configured trust stores.
func CleanCerts() error {
	if nssFlag.Value() {
		return cleanCertsNss()
	}
	return fmt.Errorf("no store was selected")
}
