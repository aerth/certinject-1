package certinject

import (
	"os"
	"testing"
	"time"
)

func TestCheckCertExpired(t *testing.T) {
	testFilename := "testdata/test_cert_file.pem"

	certExpirePeriod.SetValue(5.0)

	bytesDummy := []byte(`TEST DATA`)

	if err := injectCertFile(bytesDummy, testFilename); err != nil {
		t.Errorf("Error injecting certificate: %v", err)
		return
	}
	defer os.Remove(testFilename)

	info1, err := os.Stat(testFilename)
	if err != nil {
		t.Errorf("Error getting file info 1: %s", err)
	}

	expired1, err := checkCertExpiredNss(info1)
	if err != nil {
		t.Errorf("Error checking if file info 1 expired: %s", err)
	}

	if expired1 {
		t.Errorf("Cert expired instantly")
	}

	println("Sleeping 10 sec")
	time.Sleep(10 * time.Second)

	info2, err := os.Stat(testFilename)
	if err != nil {
		t.Errorf("Error getting file info 2: %s", err)
	}

	expired2, err := checkCertExpiredNss(info2)
	if err != nil {
		t.Errorf("Error checking if file info 2 expired: %s", err)
	}

	if !expired2 {
		t.Errorf("Cert never expired")
	}
}
