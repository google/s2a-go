package fakes2av2

import (
	"log"
	"fmt"
	_ "embed"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
)
var (
	//go:embed example_cert/client_cert.pem
	clientCert []byte
	//go:embed example_cert/server_cert.pem
	serverCert []byte
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
			if resp, err = getTlsConfiguration(req.GetGetTlsConfigurationReq()); err != nil {
				log.Printf("Fake S2A Service: failed to build SessionResp with GetTlsConfigurationResp: %v", err)
				return err
			}
		case *s2av2pb.SessionReq_OffloadPrivateKeyOperationReq:
			// TODO(rmehta19): Implement fake.
		case *s2av2pb.SessionReq_OffloadResumptionKeyOperationReq:
			// TODO(rmehta19): Implement fake.
		case *s2av2pb.SessionReq_ValidatePeerCertificateChainReq:
			// TODO(rmehta19): Implement fake.
		default:
			return fmt.Errorf("SessionReq.ReqOneof has unexpected type %T", x)
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("Fake S2A Service: failed to send SessionResp: %v", err)
			return err
		}
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
