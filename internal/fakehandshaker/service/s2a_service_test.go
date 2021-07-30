/*
 *
 * Copyright 2021 Google LLC
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

package service

import (
	"errors"
	"os"
	"strings"
	"testing"

	commonpb "github.com/s2a-go/internal/proto/common_go_proto"
	grpcpb "github.com/s2a-go/internal/proto/s2a_go_grpc_proto"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc"
	
)

const (
	testAccessToken = "test_access_token"
)

type fakeS2ASetupSessionServer struct {
	grpc.ServerStream
	recvCount int
	reqs      []*grpcpb.SessionReq
	resps     []*grpcpb.SessionResp
}

func (f *fakeS2ASetupSessionServer) Send(resp *grpcpb.SessionResp) error {
	f.resps = append(f.resps, resp)
	return nil
}

func (f *fakeS2ASetupSessionServer) Recv() (*grpcpb.SessionReq, error) {
	if f.recvCount == len(f.reqs) {
		return nil, errors.New("request buffer was fully exhausted")
	}
	req := f.reqs[f.recvCount]
	f.recvCount++
	return req, nil
}

func TestSetupSession(t *testing.T) {
	os.Setenv(accessTokenEnvVariable, "")
	for _, tc := range []struct {
		desc string
		// Note that outResps[i] is the output for reqs[i].
		reqs           []*grpcpb.SessionReq
		outResps       []*grpcpb.SessionResp
		hasNonOKStatus bool
	}{
		{
			desc: "client failure no app protocols",
			reqs: []*grpcpb.SessionReq{
				{
					ReqOneof: &grpcpb.SessionReq_ClientStart{
						ClientStart: &grpcpb.ClientSessionStartReq{},
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "client failure non initial state",
			reqs: []*grpcpb.SessionReq{
				{
					ReqOneof: &grpcpb.SessionReq_ClientStart{
						ClientStart: &grpcpb.ClientSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        commonpb.TLSVersion_TLS1_3,
							MaxTlsVersion:        commonpb.TLSVersion_TLS1_3,
							TlsCiphersuites: []commonpb.Ciphersuite{
								commonpb.Ciphersuite_AES_128_GCM_SHA256,
								commonpb.Ciphersuite_AES_256_GCM_SHA384,
								commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
				{
					ReqOneof: &grpcpb.SessionReq_ClientStart{
						ClientStart: &grpcpb.ClientSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        commonpb.TLSVersion_TLS1_3,
							MaxTlsVersion:        commonpb.TLSVersion_TLS1_3,
							TlsCiphersuites: []commonpb.Ciphersuite{
								commonpb.Ciphersuite_AES_128_GCM_SHA256,
								commonpb.Ciphersuite_AES_256_GCM_SHA384,
								commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
			},
			outResps: []*grpcpb.SessionResp{
				{
					OutFrames: []byte(clientHelloFrame),
					Status: &grpcpb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "client test",
			reqs: []*grpcpb.SessionReq{
				{
					ReqOneof: &grpcpb.SessionReq_ClientStart{
						ClientStart: &grpcpb.ClientSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        commonpb.TLSVersion_TLS1_3,
							MaxTlsVersion:        commonpb.TLSVersion_TLS1_3,
							TlsCiphersuites: []commonpb.Ciphersuite{
								commonpb.Ciphersuite_AES_128_GCM_SHA256,
								commonpb.Ciphersuite_AES_256_GCM_SHA384,
								commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
							LocalIdentity: &commonpb.Identity{
								IdentityOneof: &commonpb.Identity_Hostname{Hostname: "local hostname"},
							},
							TargetIdentities: []*commonpb.Identity{
								{
									IdentityOneof: &commonpb.Identity_SpiffeId{SpiffeId: "peer spiffe identity"},
								},
							},
						},
					},
				},
				{
					ReqOneof: &grpcpb.SessionReq_Next{
						Next: &grpcpb.SessionNextReq{
							InBytes: []byte(serverFrame),
						},
					},
				},
			},
			outResps: []*grpcpb.SessionResp{
				{
					OutFrames: []byte(clientHelloFrame),
					Status: &grpcpb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
				{
					OutFrames:     []byte(clientFinishedFrame),
					BytesConsumed: uint32(len(serverFrame)),
					Result: &grpcpb.SessionResult{
						ApplicationProtocol: grpcAppProtocol,
						State: &grpcpb.SessionState{
							TlsVersion:     commonpb.TLSVersion_TLS1_3,
							TlsCiphersuite: commonpb.Ciphersuite_AES_128_GCM_SHA256,
							InKey:          []byte(inKey),
							OutKey:         []byte(outKey),
						},
						PeerIdentity: &commonpb.Identity{
							IdentityOneof: &commonpb.Identity_SpiffeId{SpiffeId: "peer spiffe identity"},
						},
						LocalIdentity: &commonpb.Identity{
							IdentityOneof: &commonpb.Identity_Hostname{Hostname: "local hostname"},
						},
					},
					Status: &grpcpb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
		},
		{
			desc: "server failure no app protocols",
			reqs: []*grpcpb.SessionReq{
				{
					ReqOneof: &grpcpb.SessionReq_ServerStart{
						ServerStart: &grpcpb.ServerSessionStartReq{},
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "server failure non initial state",
			reqs: []*grpcpb.SessionReq{
				{
					ReqOneof: &grpcpb.SessionReq_ServerStart{
						ServerStart: &grpcpb.ServerSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        commonpb.TLSVersion_TLS1_3,
							MaxTlsVersion:        commonpb.TLSVersion_TLS1_3,
							TlsCiphersuites: []commonpb.Ciphersuite{
								commonpb.Ciphersuite_AES_128_GCM_SHA256,
								commonpb.Ciphersuite_AES_256_GCM_SHA384,
								commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
				{
					ReqOneof: &grpcpb.SessionReq_ServerStart{
						ServerStart: &grpcpb.ServerSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        commonpb.TLSVersion_TLS1_3,
							MaxTlsVersion:        commonpb.TLSVersion_TLS1_3,
							TlsCiphersuites: []commonpb.Ciphersuite{
								commonpb.Ciphersuite_AES_128_GCM_SHA256,
								commonpb.Ciphersuite_AES_256_GCM_SHA384,
								commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
						},
					},
				},
			},
			outResps: []*grpcpb.SessionResp{
				{
					Status: &grpcpb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
			hasNonOKStatus: true,
		},
		{
			desc: "server test",
			reqs: []*grpcpb.SessionReq{
				{
					ReqOneof: &grpcpb.SessionReq_ServerStart{
						ServerStart: &grpcpb.ServerSessionStartReq{
							ApplicationProtocols: []string{grpcAppProtocol},
							MinTlsVersion:        commonpb.TLSVersion_TLS1_3,
							MaxTlsVersion:        commonpb.TLSVersion_TLS1_3,
							TlsCiphersuites: []commonpb.Ciphersuite{
								commonpb.Ciphersuite_AES_128_GCM_SHA256,
								commonpb.Ciphersuite_AES_256_GCM_SHA384,
								commonpb.Ciphersuite_CHACHA20_POLY1305_SHA256,
							},
							InBytes: []byte(clientHelloFrame),
							LocalIdentities: []*commonpb.Identity{
								{
									IdentityOneof: &commonpb.Identity_Hostname{Hostname: "local hostname"},
								},
							},
						},
					},
				},
				{
					ReqOneof: &grpcpb.SessionReq_Next{
						Next: &grpcpb.SessionNextReq{
							InBytes: []byte(clientFinishedFrame),
						},
					},
				},
			},
			outResps: []*grpcpb.SessionResp{
				{
					OutFrames:     []byte(serverFrame),
					BytesConsumed: uint32(len(clientHelloFrame)),
					Status: &grpcpb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
				{
					BytesConsumed: uint32(len(clientFinishedFrame)),
					Result: &grpcpb.SessionResult{
						ApplicationProtocol: grpcAppProtocol,
						State: &grpcpb.SessionState{
							TlsVersion:     commonpb.TLSVersion_TLS1_3,
							TlsCiphersuite: commonpb.Ciphersuite_AES_128_GCM_SHA256,
							InKey:          []byte(inKey),
							OutKey:         []byte(outKey),
						},
						LocalIdentity: &commonpb.Identity{
							IdentityOneof: &commonpb.Identity_Hostname{Hostname: "local hostname"},
						},
					},
					Status: &grpcpb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
		},
		{
			desc: "resumption ticket test",
			reqs: []*grpcpb.SessionReq{
				{
					ReqOneof: &grpcpb.SessionReq_ResumptionTicket{
						ResumptionTicket: &grpcpb.ResumptionTicketReq{
							ConnectionId: 1234,
							LocalIdentity: &commonpb.Identity{
								IdentityOneof: &commonpb.Identity_Hostname{Hostname: "local hostname"},
							},
						},
					},
				},
			},
			outResps: []*grpcpb.SessionResp{
				{
					Status: &grpcpb.SessionStatus{
						Code: uint32(codes.OK),
					},
				},
			},
			hasNonOKStatus: false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			hs := FakeHandshakerService{}
			stream := &fakeS2ASetupSessionServer{reqs: tc.reqs}
			if got, want := hs.SetUpSession(stream) == nil, !tc.hasNonOKStatus; got != want {
				t.Errorf("hs.SetUpSession(%v) = (err=nil) = %v, want %v", stream, got, want)
			}
			hasNonOKStatus := false
			for i := range tc.reqs {
				if stream.resps[i].GetStatus().GetCode() != uint32(codes.OK) {
					hasNonOKStatus = true
					break
				}
				if got, want := stream.resps[i], tc.outResps[i]; !cmp.Equal(got, want) {
					t.Fatalf("stream.resps[%d] = %v, want %v", i, got, want)
				}
			}
			if got, want := hasNonOKStatus, tc.hasNonOKStatus; got != want {
				t.Errorf("hasNonOKStatus = %v, want %v", got, want)
			}
		})
	}
}

func TestAuthenticateRequest(t *testing.T) {
	for _, tc := range []struct {
		description   string
		acceptedToken string
		request       *grpcpb.SessionReq
		expectedError string
	}{
		{
			description: "access token env variable is not set",
		},
		{
			description:   "request contains valid token",
			acceptedToken: testAccessToken,
			request: &grpcpb.SessionReq{
				AuthMechanisms: []*grpcpb.AuthenticationMechanism{
					&grpcpb.AuthenticationMechanism{
						MechanismOneof: &grpcpb.AuthenticationMechanism_Token{
							Token: testAccessToken,
						},
					},
				},
			},
		},
		{
			description:   "request contains invalid token",
			acceptedToken: testAccessToken,
			request: &grpcpb.SessionReq{
				AuthMechanisms: []*grpcpb.AuthenticationMechanism{
					&grpcpb.AuthenticationMechanism{
						MechanismOneof: &grpcpb.AuthenticationMechanism_Token{
							Token: "bad_access_token",
						},
					},
				},
			},
			expectedError: "received token: bad_access_token, expected token: test_access_token",
		},
		{
			description:   "request contains valid and invalid tokens",
			acceptedToken: testAccessToken,
			request: &grpcpb.SessionReq{
				AuthMechanisms: []*grpcpb.AuthenticationMechanism{
					&grpcpb.AuthenticationMechanism{
						MechanismOneof: &grpcpb.AuthenticationMechanism_Token{
							Token: testAccessToken,
						},
					},
					&grpcpb.AuthenticationMechanism{
						MechanismOneof: &grpcpb.AuthenticationMechanism_Token{
							Token: "bad_access_token",
						},
					},
				},
			},
			expectedError: "received token: bad_access_token, expected token: test_access_token",
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			os.Setenv(accessTokenEnvVariable, tc.acceptedToken)
			hs := &FakeHandshakerService{}
			err := hs.authenticateRequest(tc.request)
			if got, want := (err == nil), (tc.expectedError == ""); got != want {
				t.Errorf("(err == nil): %t, (tc.expectedError == \"\"): %t", got, want)
			}
			if err != nil && !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("hs.authenticateRequest(%v)=%v, expected error to have substring: %v", tc.request, err, tc.expectedError)
			}
		})
	}
}
