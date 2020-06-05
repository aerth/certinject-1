package certinject

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Injects a certificate by writing to a file.  Might be relevant for non-CryptoAPI trust stores.
func injectCertFile(derBytes []byte, fileName string) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	err := ioutil.WriteFile(fileName, pemBytes, 0644)
	if err != nil {
		return fmt.Errorf("writing cert: %v", err)
	}
	return nil
}
