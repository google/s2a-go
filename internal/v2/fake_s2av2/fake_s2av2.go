package fake_s2av2

import (
	"crypto/tls"
	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
	commonpb "github.com/google/s2a-go/internal/proto/v2/common_go_proto"
)

type Server struct {
	pb.UnimplementedS2AServiceServer
}

func (s *Server) GetTlsConfiguration(ctx context.Context, req *s2av2pb.GetTlsConfigurationReq) (*s2av2pb.GetTlsConfigurationResp, error) {
	if s2av2.GetConnectionSide() == commonpb.ConnectionSide_CONNECTION_SIDE_CLIENT {
		return &s2av2pb.GetTlsConfigurationResp {
			ClientTlsConfiguration: {
				certificate_chain: []string{
					{/*TODO(rmehta19)*/},
				},
				min_tls_version: commonpb.TLSVersion_TLS_VERSION_1_3,
				max_tls_version: commonpb.TLSVersion_TLS_VERSION_1_3,
				handshake_ciphersuites: commonpb.HandshakeCiphersuite_HANDSHAKE_CIPHERSUITE_UNSPECIFIED,
				record_ciphersuites: commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_UNSPECIFIED,
			},
		}, nil
	}
	else if s2av2.GetConnectionSide() == commonpb.ConnectionSide_CONNECTION_SIDE_SERVER {
		return &s2av2pb.GetTlsConfigurationResp {
			certificate_chain: []string{
				{/*TODO(rmehta19)*/},
			},
			min_tls_version: commonpb.TLSVersion_TLS_VERSION_1_3,
			max_tls_version: commonpb.TLSVersion_TLS_VERSION_1_3,
			handshake_ciphersuites: commonpb.HandshakeCiphersuite_HANDSHAKE_CIPHERSUITE_UNSPECIFIED,
			record_ciphersuites: commonpb.RecordCiphersuite_RECORD_CIPHERSUITE_UNSPECIFIED,
			tls_resumption_enabled: false,
			request_client_certificate: s2av2pb.GetTlsConfigurationResp_ServerTlsConfiguration_REQUEST_AND_VERIFY,
			max_overhead_of_ticket_aead: 0,
		}, nil
	}
	else {
		return nil, nil
	}
}

