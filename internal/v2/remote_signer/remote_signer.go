// Remote signer library that offloads private key operations to S2Av2.
package remotesigner

import (
	"io"
	"crypto"
	"crypto/rsa"
	"crypto/x509"

	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpbv1 "github.com/google/s2a-go/internal/proto/common_go_proto"
)

// remoteSigner implementes the crypto.Signer interface.
type remoteSigner struct {
	leafCert *x509.Certificate
	cstream s2av2pb.S2AService_SetUpSessionClient
	localIdentity *commonpbv1.Identity
}


// New returns an instance of RemoteSigner, an implementation of the
// crypto.Signer interface.
func New(leafCert *x509.Certificate, cstream s2av2pb.S2AService_SetUpSessionClient, localIdentity *commonpbv1.Identity) crypto.Signer {
	return &remoteSigner{leafCert, cstream, localIdentity}
}

func (s *remoteSigner) Public() crypto.PublicKey {
	return s.leafCert.PublicKey
}

func (s *remoteSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Send request to S2Av2 to perform private key operation.
	if err := s.cstream.Send(&s2av2pb.SessionReq {
		LocalIdentity: s.localIdentity,
		ReqOneof: &s2av2pb.SessionReq_OffloadPrivateKeyOperationReq {
			&s2av2pb.OffloadPrivateKeyOperationReq {
				Operation: s2av2pb.OffloadPrivateKeyOperationReq_SIGN,
				// TODO(rmehta19): Use Signtuare Algorithm from s.leafCert. To do this,
				// need to create a mapping from x509 Signature Algorithm:
				// https://pkg.go.dev/crypto/x509#SignatureAlgorithm
				// to s2av2 signature algorithm: https://github.com/google/s2a-go/blob/
				// 2eb8a32e71c9747a4e56196460bfd0feafb5189b/internal/proto/v2/
				// s2a_go_proto/s2a.pb.go#L43
				SignatureAlgorithm: getSignatureAlgorithm(opts),
				InBytes: []byte(digest),
			},
		},
	}); err != nil {
		return nil, err
	}

	// Get the response containing config from S2Av2.
	resp, err := s.cstream.Recv()
	if err != nil {
		return nil, err
	}

	return resp.GetOffloadPrivateKeyOperationResp().GetOutBytes(), nil
}

// getCert returns the leafCert field in s.
func (s *remoteSigner) getCert() *x509.Certificate {
	return s.leafCert
}

// getStream returns the cstream field in s.
func (s *remoteSigner) getStream() s2av2pb.S2AService_SetUpSessionClient {
	return s.cstream
}

// getLocalIdentity returns the localIdentity field in s.
func (s *remoteSigner) getLocalIdentity() *commonpbv1.Identity {
	return s.localIdentity
}

// getSignatureAlgorithm analyzes opts and determines signature algorithm to be
// used.
// TODO(rmehta19): fill in rest of logic(coverage of all signature algorithms).
func getSignatureAlgorithm(opts crypto.SignerOpts) s2av2pb.SignatureAlgorithm {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PSS_RSAE_SHA256
	} else if opts == crypto.SHA256 {
		return s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_RSA_PKCS1_SHA256
	} else {
		return s2av2pb.SignatureAlgorithm_S2A_SSL_SIGN_UNSPECIFIED
	}
}
