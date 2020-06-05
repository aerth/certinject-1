package certinject

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var certDir = cflag.String(flagGroup, "nsscertdir", "", "Directory to store "+
	"certificate files.  Only use a directory that only ncdns can write "+
	"to.  (Required if nss is set.)")
var nssDir = cflag.String(flagGroup, "nssdbdir", "", "Directory that "+
	"contains NSS's cert9.db.  (Required if nss is set.)")

func injectCertNss(derBytes []byte) error {
	if certDir.Value() == "" {
		return fmt.Errorf("Empty nsscertdir configuration.")
	}

	if nssDir.Value() == "" {
		return fmt.Errorf("Empty nssdbdir configuration.")
	}

	fingerprint := sha256.Sum256(derBytes)

	fingerprintHex := hex.EncodeToString(fingerprint[:])

	path := certDir.Value() + "/" + fingerprintHex + ".pem"

	injectCertFile(derBytes, path)

	nickname := nicknameFromFingerprintHexNss(fingerprintHex)

	// TODO: check whether we can replace CP with just P.
	cmd := exec.Command(nssCertutilName, "-d", "sql:"+nssDir.Value(), "-A",
		"-t", "CP,,", "-n", nickname, "-a", "-i", path)

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(stdoutStderr), "SEC_ERROR_PKCS11_GENERAL_ERROR") {
			log.Warn("Temporary SEC_ERROR_PKCS11_GENERAL_ERROR injecting certificate to NSS database; retrying in 1ms...")
			time.Sleep(1 * time.Millisecond)
			return injectCertNss(derBytes)
		}
		return fmt.Errorf("Error injecting cert to NSS database: %s\n%s", err, stdoutStderr)
	}
	return nil
}

func cleanCertsNss() error {
	if certDir.Value() == "" {
		return fmt.Errorf("Empty nsscertdir configuration.")
	}

	if nssDir.Value() == "" {
		return fmt.Errorf("Empty nssdbdir configuration.")
	}

	certFiles, err := ioutil.ReadDir(certDir.Value() + "/")
	if err != nil {
		return fmt.Errorf("Error enumerating files in cert directory: %v", err)
	}

	// for all Namecoin certs in the folder
	var errors []error
	var retry = false
	for _, f := range certFiles {
		// Check if the cert is expired
		expired, err := checkCertExpiredNss(f)
		if err != nil {
			errors = append(errors, fmt.Errorf("Error checking if NSS cert is expired: %v", err))
			continue
		}

		// delete the cert if it's expired
		if expired {
			filename := f.Name()

			fingerprintHex := strings.Replace(filename, ".pem", "",
				-1)

			nickname := nicknameFromFingerprintHexNss(
				fingerprintHex)

			// Delete the cert from NSS
			cmd := exec.Command(nssCertutilName, "-d", "sql:"+
				nssDir.Value(), "-D", "-n", nickname)

			stdoutStderr, err := cmd.CombinedOutput()

			switch {
			case err == nil: // skip
			case strings.Contains(string(stdoutStderr), "SEC_ERROR_UNRECOGNIZED_OID"):
				log.Warn("Tried to delete certificate from NSS database, " +
					"but the certificate was already not present in NSS database")
			case strings.Contains(string(stdoutStderr), "SEC_ERROR_PKCS11_GENERAL_ERROR"):
				log.Warn("Temporary SEC_ERROR_PKCS11_GENERAL_ERROR deleting certificate from NSS database; retrying in 1ms...")
				time.Sleep(1 * time.Millisecond)
				_, err = cmd.CombinedOutput()
				if err != nil {
					errors = append(errors, err)
					retry = true
					continue
				}
			default:
				log.Fatalf("Error deleting cert from NSS database: %v\n%s", err, stdoutStderr)
			}

			if !retry {

				// Also delete the cert from the filesystem
				err = os.Remove(certDir.Value() + "/" + filename)
				if err != nil {
					return fmt.Errorf("Error deleting NSS cert from filesystem: %v", err)
				}
			}
		}
	}

	if len(errors) != 0 {
		return fmt.Errorf("%v errors found: %v", len(errors), errors)
	}
	return nil

}

func checkCertExpiredNss(certFile os.FileInfo) (bool, error) {
	// Get the last modified time
	certFileModTime := certFile.ModTime()

	age := time.Since(certFileModTime)
	ageSeconds := age.Seconds()

	// If the cert's last modified timestamp differs too much from the
	// current time in either direction, consider it expired
	expired := math.Abs(ageSeconds) > float64(certExpirePeriod.Value())

	log.Debugf("Age of certificate: %s = %f seconds; expired = %t", age, ageSeconds, expired)

	return expired, nil
}

func nicknameFromFingerprintHexNss(fingerprintHex string) string {
	return "Namecoin-" + fingerprintHex
}
