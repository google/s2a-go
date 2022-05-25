// Static implementation of Remote Signer (no calls to S2Av2).
// Remote Signer is an implementation of the Signer interface
package remote_signer

import (
	"crypto/tls"
	"crypto"
)

func name_function(cert tls.Certificate) crypto.Signer {

}

func (signer crypto.Signer) Public() crypto.PublicKey {
	return signer.Public()
}

func (signer crypto.Signer) Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error) {
	// TODO : OffloadPrivateKeyOperation RPC to S2A
}
