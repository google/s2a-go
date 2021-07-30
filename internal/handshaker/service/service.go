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

// Package service is a utility for calling the S2A handshaker service.
package service

import (
	"sync"

	_ "go/tools/nogo/allowlist/grpc/insecure" // To suppress go/nogo-check for using grpc.WithInsecure().
	grpc "google.golang.org/grpc"
)

var (
	// mu guards hsConnMap and hsDialer.
	mu sync.Mutex
	// hsConnMap represents a mapping from an S2A handshaker service address
	// to a corresponding connection to an S2A handshaker service instance.
	hsConnMap = make(map[string]*grpc.ClientConn)
	// hsDialer will be reassigned in tests.
	hsDialer = grpc.Dial
)

// Dial dials the S2A handshaker service. If a connection has already been
// established, this function returns it. Otherwise, a new connection is
// created.
func Dial(handshakerServiceAddress string) (*grpc.ClientConn, error) {
	mu.Lock()
	defer mu.Unlock()

	hsConn, ok := hsConnMap[handshakerServiceAddress]
	if !ok {
		// Create a new connection to the S2A handshaker service. Note that
		// this connection stays open until the application is closed.
		var err error
		// suppress go/nogo-check#disallowedfunction third_party/golang/grpc/grpc.WithInsecure
		hsConn, err = hsDialer(handshakerServiceAddress, grpc.WithInsecure())
		if err != nil {
			return nil, err
		}
		hsConnMap[handshakerServiceAddress] = hsConn
	}
	return hsConn, nil
}
