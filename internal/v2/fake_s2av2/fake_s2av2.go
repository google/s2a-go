package fake_s2av2

import (
	"context"

	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
)

type Server struct {
	s2av2pb.UnimplementedS2AServiceServer
}

func (s *Server) GetTlsConfiguration(ctx context.Context, req *s2av2pb.GetTlsConfigurationReq) (*s2av2pb.GetTlsConfigurationResp, error) {
	if req.GetConnectionSide() == commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT {
		return &s2av2pb.GetTlsConfigurationResp {
			TlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration_{
				&s2av2pb.GetTlsConfigurationResp_ClientTlsConfiguration{
					CertificateChain: []string{
						/*TODO(rmehta19)*/
						"",
					},
					MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
					MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
					HandshakeCiphersuites: []commonpb.HandshakeCiphersuite{},
					RecordCiphersuites: []commonpb.RecordCiphersuite{},
				},
			},
		}, nil
	} else if req.GetConnectionSide() == commonpb.ConnectionSide_CONNECTION_SIDE_SERVER {
		return &s2av2pb.GetTlsConfigurationResp {
			TlsConfiguration: &s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_{
				&s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration{
					CertificateChain: []string{
						/*TODO(rmehta19)*/
						"",
					},
					MinTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
					MaxTlsVersion: commonpb.TLSVersion_TLS_VERSION_1_3,
					HandshakeCiphersuites: []commonpb.HandshakeCiphersuite{},
					RecordCiphersuites: []commonpb.RecordCiphersuite{},
					TlsResumptionEnabled: false,
					RequestClientCertificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_AND_VERIFY,
					MaxOverheadOfTicketAead: 0,
				},
			},
		}, nil
	} else {
		return nil, nil /*TODO(rmehta19): replace with some error message.*/
	}
}

