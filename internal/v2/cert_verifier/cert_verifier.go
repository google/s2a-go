// Certificate verifier library that offloads verifications to S2Av2.
package certverifier

import (
	"fmt"
	"crypto/x509"
	"google.golang.org/grpc/codes"

	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

// VerifyClientCertificateChain builds a SessionReq, sends it to S2Av2 and
// receives a SessionResp.
func VerifyClientCertificateChain(cstream s2av2pb.S2AService_SetUpSessionClient) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Offload verification to S2Av2.
		if err := cstream.Send(&s2av2pb.SessionReq {
			ReqOneof: &s2av2pb.SessionReq_ValidatePeerCertificateChainReq {
				&s2av2pb.ValidatePeerCertificateChainReq {
					Mode: s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE,
					PeerOneof: &s2av2pb.ValidatePeerCertificateChainReq_ClientPeer_ {
						&s2av2pb.ValidatePeerCertificateChainReq_ClientPeer {
							CertificateChain: rawCerts,
						},
					},
				},
			},
		}); err != nil {
			return err
		}

		// Get the response from S2Av2.
		resp, err := cstream.Recv()
		if err != nil {
			return err
		}

		// Parse the response
		if (resp.GetStatus() != nil) && (resp.GetStatus().Code != uint32(codes.OK)) {
			return fmt.Errorf("Failed to offload client cert verification to S2A: %d, %v", resp.GetStatus().Code, resp.GetStatus().Details)

		}
		return nil
	}
}

// VerifyServerCertificateChain builds a SessionReq, sends it to S2Av2 and
// receives a SessionResp.
func VerifyServerCertificateChain(hostname string, cstream s2av2pb.S2AService_SetUpSessionClient) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Offload verification to S2Av2.
		if err := cstream.Send(&s2av2pb.SessionReq {
			ReqOneof: &s2av2pb.SessionReq_ValidatePeerCertificateChainReq {
				&s2av2pb.ValidatePeerCertificateChainReq {
					Mode: s2av2pb.ValidatePeerCertificateChainReq_CONNECT_TO_GOOGLE,
					PeerOneof: &s2av2pb.ValidatePeerCertificateChainReq_ServerPeer_ {
						&s2av2pb.ValidatePeerCertificateChainReq_ServerPeer {
							CertificateChain: rawCerts,
							ServerHostname: hostname,
						},
					},
				},
			},
		}); err != nil {
			return err
		}

		// Get the response from S2Av2.
		resp, err := cstream.Recv()
		if err != nil {
			return err
		}

		// Parse the response
		if (resp.GetStatus() != nil) && (resp.GetStatus().Code != uint32(codes.OK)) {
			return fmt.Errorf("Failed to offload client cert verification to S2A: %d, %v", resp.GetStatus().Code, resp.GetStatus().Details)
		}
		return nil
	}
}
