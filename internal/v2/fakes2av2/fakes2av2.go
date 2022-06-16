package fakes2av2

import (
	"log"
	"fmt"
	"time"
	"errors"
	"crypto/x509"
	_ "embed"
	s2av2ctx "github.com/google/s2a-go/internal/proto/v2/s2a_context_go_proto"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
)
var (
	//go:embed example_cert/client_cert.pem
	clientCert []byte
	//go:embed example_cert/client_cert.der
	clientDERCert []byte
	//go:embed example_cert/server_cert.pem
	serverCert []byte
	//go:embed example_cert/server_cert.der
	serverDERCert []byte
)

// Server is a fake S2A Server for testing.
type Server struct {
	s2av2pb.UnimplementedS2AServiceServer
}

// SetUpSession receives SessionReq, performs request, and returns a
// SessionResp, all on the server stream.
func (s *Server) SetUpSession(stream s2av2pb.S2AService_SetUpSessionServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Fake S2A Service: failed to receive SessionReq: %v", err)
			return err
		}
		// Call one of the 4 possible RespOneof's
		// TODO(rmehta19): Consider validating the body of the request.
		var resp *s2av2pb.SessionResp
		switch x := req.ReqOneof.(type) {
		case *s2av2pb.SessionReq_GetTlsConfigurationReq:
			resp, err = getTlsConfiguration(req.GetGetTlsConfigurationReq())
			if err != nil {
				log.Printf("Fake S2A Service: failed to build SessionResp with GetTlsConfigurationResp: %v", err)
				return err
			}
		case *s2av2pb.SessionReq_OffloadPrivateKeyOperationReq:
			// TODO(rmehta19): Implement fake.
		case *s2av2pb.SessionReq_OffloadResumptionKeyOperationReq:
			// TODO(rmehta19): Implement fake.
		case *s2av2pb.SessionReq_ValidatePeerCertificateChainReq:
			resp, err = validatePeerCertificateChain(req.GetValidatePeerCertificateChainReq())
			if err != nil {
				log.Printf("Fake S2A Service: failed to build SessionResp with ValidatePeerCertificateChainResp: %v", err)
				return err
			}
		default:
			return fmt.Errorf("SessionReq.ReqOneof has unexpected type %T", x)
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Fake S2A Service: failed to send SessionResp: %v", err)
			return err
		}
	}
}

func validatePeerCertificateChain(req *s2av2pb.ValidatePeerCertificateChainReq) (*s2av2pb.SessionResp, error) {
	switch x := req.PeerOneof.(type) {
	case *s2av2pb.ValidatePeerCertificateChainReq_ClientPeer_:
		return verifyClientPeer(req)
	case *s2av2pb.ValidatePeerCertificateChainReq_ServerPeer_:
		return verifyServerPeer(req)
	default:
		err := errors.New(fmt.Sprintf("Peer Verification failed: invalid Peer type %T", x))
		return buildValidatePeerCertificateChainSessionResp(3, err.Error(), s2av2pb.ValidatePeerCertificateChainResp_FAILURE, err.Error(),  &s2av2ctx.S2AContext{}), err
	}
}

func getTlsConfiguration(req *s2av2pb.GetTlsConfigurationReq) (*s2av2pb.SessionResp, error) {
	if req.GetConnectionSide() == commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT {
		return &s2av2pb.SessionResp {
			Status: &s2av2pb.Status {
				Code: 0,
			},
			RespOneof: &s2av2pb.SessionResp_GetTlsConfigurationResp {
				GetTlsConfigurationResp: &s2av2pb.GetTlsConfigurationResp {
					TlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration_ {
						&s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration {
							CertificateChain: []string{
								string(clientCert),
							},
							MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
							MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
							HandshakeCiphersuites: []commonpb.HandshakeCiphersuite{},
							RecordCiphersuites: []commonpb.RecordCiphersuite {
								commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_128_GCM_SHA256,
								commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_256_GCM_SHA384,
								commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
			},
		}, nil
	} else if req.GetConnectionSide() == commonpb.ConnectionSide_CONNECTION_SIDE_SERVER {
		return &s2av2pb.SessionResp {
			Status: &s2av2pb.Status {
				Code: 0,
			},
			RespOneof: &s2av2pb.SessionResp_GetTlsConfigurationResp {
				GetTlsConfigurationResp: &s2av2pb.GetTlsConfigurationResp {
					TlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_{
						&s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
							CertificateChain: []string{
								string(serverCert),
							},
							MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
							MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
							HandshakeCiphersuites: []commonpb.HandshakeCiphersuite{},
							RecordCiphersuites: []commonpb.RecordCiphersuite {
								commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_128_GCM_SHA256,
								commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_AES_256_GCM_SHA384,
								commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_CHACHA20_POLY1305_SHA256,
							},
							TlsResumptionEnabled: false,
							RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_AND_VERIFY,
							MaxOverheadOfTicketAead: 0,
						},
					},
				},
			},
		}, nil
	} else {
		err := fmt.Errorf("unknown ConnectionSide, req.GetConnectionSide() returned %v", req.GetConnectionSide())
		return nil, err
	}
}

func buildValidatePeerCertificateChainSessionResp(StatusCode uint32, StatusDetails string, ValidationResult s2av2pb.ValidatePeerCertificateChainResp_ValidationResult, ValidationDetails string, Context*s2av2ctx.S2AContext) *s2av2pb.SessionResp{
	return &s2av2pb.SessionResp {
		Status: &s2av2pb.Status {
			Code: StatusCode,
			Details: StatusDetails,
		},
		RespOneof: &s2av2pb.SessionResp_ValidatePeerCertificateChainResp {
			&s2av2pb.ValidatePeerCertificateChainResp {
				ValidationResult: ValidationResult,
				ValidationDetails: ValidationDetails,
				Context: Context,
			},
		},
	}
}

func verifyClientPeer(req *s2av2pb.ValidatePeerCertificateChainReq) (*s2av2pb.SessionResp, error) {
	derCertChain := req.GetClientPeer().CertificateChain
	if len(derCertChain) == 0 {
		err := errors.New("Client Peer Verification failed: client cert chain is empty.")
		return buildValidatePeerCertificateChainSessionResp(3, err.Error(), s2av2pb.ValidatePeerCertificateChainResp_FAILURE, err.Error(), &s2av2ctx.S2AContext{}), err
	}

	// Obtain the set of root certificates.
	rootCertPool := x509.NewCertPool()
	if ok := rootCertPool.AppendCertsFromPEM(clientCert); ok != true {
		err := errors.New("Client Peer Verification failed: S2Av2 could not obtain/parse roots.")
		return buildValidatePeerCertificateChainSessionResp(13, err.Error(), s2av2pb.ValidatePeerCertificateChainResp_FAILURE, err.Error(), &s2av2ctx.S2AContext{}), err
	}

	// Set the Intermediates: certs between leaf and root, excluding the leaf and root.
	intermediateCertPool := x509.NewCertPool()
	for i := 1; i < (len(derCertChain)); i++ {
		x509Cert, err := x509.ParseCertificate(derCertChain[i])
		if err != nil {
			return buildValidatePeerCertificateChainSessionResp(3, err.Error(), s2av2pb.ValidatePeerCertificateChainResp_FAILURE, err.Error(), &s2av2ctx.S2AContext{}), err
		}
		intermediateCertPool.AddCert(x509Cert)
	}

	// Verify the leaf certificate.
	opts := x509.VerifyOptions{
		CurrentTime: time.Now(),
		Roots: rootCertPool,
		Intermediates: intermediateCertPool,
	}
	x509LeafCert, err := x509.ParseCertificate(derCertChain[0])
	if err != nil {
		s := fmt.Sprintf("Client Peer Verification failed: %v", err)
		return buildValidatePeerCertificateChainSessionResp(3, s, s2av2pb.ValidatePeerCertificateChainResp_FAILURE, s, &s2av2ctx.S2AContext{}), err
	}
	if _, err := x509LeafCert.Verify(opts); err != nil {
		s := fmt.Sprintf("Client Peer Verification failed: %v", err)
		return buildValidatePeerCertificateChainSessionResp(3, s, s2av2pb.ValidatePeerCertificateChainResp_FAILURE, s, &s2av2ctx.S2AContext{}), err
	}
	return buildValidatePeerCertificateChainSessionResp(0, "", s2av2pb.ValidatePeerCertificateChainResp_SUCCESS, "Client Peer Verification succeeded", &s2av2ctx.S2AContext{}), nil
}

func verifyServerPeer(req *s2av2pb.ValidatePeerCertificateChainReq) (*s2av2pb.SessionResp, error) {
	derCertChain := req.GetServerPeer().CertificateChain
	if len(derCertChain) == 0 {
		err := errors.New("Server Peer Verification failed: server cert chain is empty.")
		return buildValidatePeerCertificateChainSessionResp(3, err.Error(), s2av2pb.ValidatePeerCertificateChainResp_FAILURE, err.Error(), &s2av2ctx.S2AContext{}), err
	}

	// Obtain the set of root certificates.
	rootCertPool := x509.NewCertPool()
	if ok := rootCertPool.AppendCertsFromPEM(serverCert); ok != true {
		err := errors.New("Server Peer Verification failed: S2Av2 could not obtain/parse roots.")
		return buildValidatePeerCertificateChainSessionResp(13, err.Error(), s2av2pb.ValidatePeerCertificateChainResp_FAILURE, err.Error(), &s2av2ctx.S2AContext{}), err
	}


	// Set the Intermediates: certs between leaf and root, excluding the leaf and root.
	intermediateCertPool := x509.NewCertPool()
	for i := 1; i < (len(derCertChain)); i++ {
		x509Cert, err := x509.ParseCertificate(derCertChain[i])
		if err != nil {
			return buildValidatePeerCertificateChainSessionResp(3, err.Error(), s2av2pb.ValidatePeerCertificateChainResp_FAILURE, err.Error(), &s2av2ctx.S2AContext{}), err
		}
		intermediateCertPool.AddCert(x509Cert)
	}

	// Verify the leaf certificate.
	opts := x509.VerifyOptions{
		CurrentTime: time.Now(),
		Roots: rootCertPool,
		Intermediates: intermediateCertPool,
	}
	x509LeafCert, err := x509.ParseCertificate(derCertChain[0])
	if err != nil {
		s := fmt.Sprintf("Server Peer Verification failed: %v", err)
		return buildValidatePeerCertificateChainSessionResp(3, s, s2av2pb.ValidatePeerCertificateChainResp_FAILURE, s, &s2av2ctx.S2AContext{}), err
	}
	if _, err := x509LeafCert.Verify(opts); err != nil {
		s := fmt.Sprintf("Server Peer Verification failed: %v", err)
		return buildValidatePeerCertificateChainSessionResp(3, s, s2av2pb.ValidatePeerCertificateChainResp_FAILURE, s, &s2av2ctx.S2AContext{}), err
	}

	return buildValidatePeerCertificateChainSessionResp(0, "", s2av2pb.ValidatePeerCertificateChainResp_SUCCESS, "Server Peer Verification succeeded",&s2av2ctx.S2AContext{}), nil
}
