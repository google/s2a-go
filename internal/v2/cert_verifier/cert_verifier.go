// Certificate verifier library that offloads verifications to S2Av2.
package certverifier

import (
	"crypto/x509"
	"fmt"
	"time"
)

// VerifyClientCertificateChain verifies a client's certificate chain against
// the roots in the provided pool and checks that the common name in the
// client's leaf certificate matches the expected common name.
func VerifyClientCertificateChain(expectedCommonName string, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("ParseCertificate failed: %v", err)
		}

		opts := x509.VerifyOptions{
			CurrentTime: time.Now(),
			Roots:       pool,
		}

		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		if cert.Subject.CommonName != expectedCommonName {
			return fmt.Errorf("certificate had Common Name %q, expected %q", cert.Subject.CommonName, expectedCommonName)
		}
		return nil
	}
}

// VerifyServerCertificateChain verifies a servers' certificate chain against
// the roots in the provided pool and checks that the common name in the
// servers' leaf certificate matches the expected common name.
func VerifyServerCertificateChain(expectedCommonName string, hostname string, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("ParseCertificate failed: %v", err)
		}

		opts := x509.VerifyOptions{
			CurrentTime: time.Now(),
			Roots:       pool,
		}

		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		if cert.Subject.CommonName != expectedCommonName {
			return fmt.Errorf("certificate had Common Name %q, expected %q", cert.Subject.CommonName, expectedCommonName)
		}
		return nil
	}
}
