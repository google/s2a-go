package certificate_verifier

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func VerifyClientCertificateChain(pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate to verify")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("x509.ParseCertificate(rawCerts[0]) returned error: %v", err)
		}

		opts := x509.VerifyOptions{
			CurrentTime: time.Now(),
			Roots:       pool,
		}

		if _, err = cert.Verify(opts); err != nil {
			return err
		}
		return nil
	}
}

func VerifyServerCertificateChain(hostname string, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate to verify")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("x509.ParseCertificate(rawCerts[0]) returned error: %v", err)
		}

		opts := x509.VerifyOptions{
			CurrentTime: time.Now(),
			Roots:       pool,
		}

		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		if cert.Subject.CommonName != instanceName {
			return fmt.Errorf("certificate had Common Name %q, expected %q", cert.Subject.CommonName, instanceName)
		}
		return nil
	}
}

