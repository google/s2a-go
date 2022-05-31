// Remote signer library that offloads private key operations to S2Av2.
package remotesigner

import (
	"crypto"
	"crypto/tls"
)

// New returns an instance of RemoteSigner, an implementation of the
// crypto.Signer interface.
func New(cert *tls.Certificate) crypto.Signer {
	// TODO(rmehta19): Implement crypto.Signer interface that calls S2Av2.
	return cert.PrivateKey.(crypto.Signer)
}
