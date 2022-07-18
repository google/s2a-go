/*
 *
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package certverifier offloads verifications to S2Av2.
package certverifier

import (
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/codes"

	s2av2pb "github.com/google/s2a-go/internal/proto/v2/s2a_go_proto"
)

// VerifyClientCertificateChain builds a SessionReq, sends it to S2Av2 and
// receives a SessionResp.
func VerifyClientCertificateChain(verificationMode s2av2pb.ValidatePeerCertificateChainReq_VerificationMode, cstream s2av2pb.S2AService_SetUpSessionClient) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Offload verification to S2Av2.
		if err := cstream.Send(&s2av2pb.SessionReq{
			ReqOneof: &s2av2pb.SessionReq_ValidatePeerCertificateChainReq{
				ValidatePeerCertificateChainReq: &s2av2pb.ValidatePeerCertificateChainReq{
					Mode: verificationMode,
					PeerOneof: &s2av2pb.ValidatePeerCertificateChainReq_ClientPeer_{
						ClientPeer: &s2av2pb.ValidatePeerCertificateChainReq_ClientPeer{
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

		// Parse the response.
		if (resp.GetStatus() != nil) && (resp.GetStatus().Code != uint32(codes.OK)) {
			return fmt.Errorf("failed to offload client cert verification to S2A: %d, %v", resp.GetStatus().Code, resp.GetStatus().Details)

		}
		return nil
	}
}

// VerifyServerCertificateChain builds a SessionReq, sends it to S2Av2 and
// receives a SessionResp.
func VerifyServerCertificateChain(hostname string, verificationMode s2av2pb.ValidatePeerCertificateChainReq_VerificationMode, cstream s2av2pb.S2AService_SetUpSessionClient) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// Offload verification to S2Av2.
		if err := cstream.Send(&s2av2pb.SessionReq{
			ReqOneof: &s2av2pb.SessionReq_ValidatePeerCertificateChainReq{
				ValidatePeerCertificateChainReq: &s2av2pb.ValidatePeerCertificateChainReq{
					Mode: verificationMode,
					PeerOneof: &s2av2pb.ValidatePeerCertificateChainReq_ServerPeer_{
						ServerPeer: &s2av2pb.ValidatePeerCertificateChainReq_ServerPeer{
							CertificateChain: rawCerts,
							ServerHostname:   hostname,
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

		// Parse the response.
		if (resp.GetStatus() != nil) && (resp.GetStatus().Code != uint32(codes.OK)) {
			return fmt.Errorf("failed to offload client cert verification to S2A: %d, %v", resp.GetStatus().Code, resp.GetStatus().Details)
		}
		return nil
	}
}
