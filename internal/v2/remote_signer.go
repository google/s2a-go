// Static implementation of TLS Configuration Store (no calls to S2Av2)
package remote_signer

import (
	"crypto/tls"
	"crypto"
)

var (
	pubkey []byte
)

func (p PrivateKey) Public() crypto.PublicKey {
	return pubkey
}

func (p PrivateKey) Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error) {

}
