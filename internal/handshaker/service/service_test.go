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
	"context"
	"crypto/tls"
	"google.golang.org/grpc/credentials"
	"os"
	"testing"

	grpc "google.golang.org/grpc"
)

const (
	testAddress1 = "test_address_1"
	testAddress2 = "test_address_2"
	testAddress3 = "test_address_3"
)

func TestDial(t *testing.T) {
	defer func() func() {
		temp := hsDialer
		hsDialer = func(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
			return &grpc.ClientConn{}, nil
		}
		return func() {
			hsDialer = temp
		}
	}()

	ctx := context.Background()

	// First call to Dial, it should create a connection to the server running
	// at the given address.
	conn1, err := Dial(ctx, testAddress1, nil)
	if err != nil {
		t.Fatalf("first call to Dial(%v) failed: %v", testAddress1, err)
	}
	if conn1 == nil {
		t.Fatalf("first call to Dial(%v)=(nil, _), want not nil", testAddress1)
	}
	if got, want := hsConnMap[testAddress1], conn1; got != want {
		t.Fatalf("hsConnMap[%v] = %v, want %v", testAddress1, got, want)
	}

	// Second call to Dial should return conn1 above.
	conn2, err := Dial(ctx, testAddress1, nil)
	if err != nil {
		t.Fatalf("second call to Dial(%v) failed: %v", testAddress1, err)
	}
	if got, want := conn2, conn1; got != want {
		t.Fatalf("second call to Dial(%v)=(%v, _), want (%v, _)", testAddress1, got, want)
	}
	if got, want := hsConnMap[testAddress1], conn1; got != want {
		t.Fatalf("hsConnMap[%v] = %v, want %v", testAddress1, got, want)
	}

	// Third call to Dial using a different address should create a new
	// connection.
	conn3, err := Dial(ctx, testAddress2, nil)
	if err != nil {
		t.Fatalf("third call to Dial(%v) failed: %v", testAddress2, err)
	}
	if conn3 == nil {
		t.Fatalf("third call to Dial(%v)=(nil, _), want not nil", testAddress2)
	}
	if got, want := hsConnMap[testAddress2], conn3; got != want {
		t.Fatalf("hsConnMap[%v] = %v, want %v", testAddress2, got, want)
	}
	if got, want := conn2 == conn3, false; got != want {
		t.Fatalf("(conn2 == conn3) = %v, want %v", got, want)
	}

	// Connect to an address with transportCredentials.
	conn4, err := Dial(ctx, testAddress3, credentials.NewTLS(&tls.Config{}))
	if err != nil {
		t.Fatalf("first call to Dial(%v) failed: %v", testAddress3, err)
	}
	if conn4 == nil {
		t.Fatalf("first call to Dial(%v)=(nil, _), want not nil", testAddress3)
	}
	if got, want := hsConnMap[testAddress3], conn4; got != want {
		t.Fatalf("hsConnMap[%v] = %v, want %v", testAddress3, got, want)
	}
}

func TestAppEngineSpecificDialOptions(t *testing.T) {
	if enableAppEngineDialer() {
		t.Fatalf("expected enableAppEngineDialer to be false")
	}
	if appEngineDialerHook != nil {
		t.Fatalf("expected appEngineDialerHook to be nil")
	}
}

func TestEnableAppEngineDialer(t *testing.T) {
	oldEnvValue := os.Getenv(enableAppEngineDialerEnv)
	defer os.Setenv(enableAppEngineDialerEnv, oldEnvValue)

	// Unset the environment var
	os.Unsetenv(enableAppEngineDialerEnv)
	if got, want := enableAppEngineDialer(), false; got != want {
		t.Fatalf("enableAppEngineDialer should default to false")
	}

	// Set the environment var to empty string
	os.Setenv(enableAppEngineDialerEnv, "")
	if got, want := enableAppEngineDialer(), false; got != want {
		t.Fatalf("enableAppEngineDialer should default to false")
	}

	// Set the environment var to true
	os.Setenv(enableAppEngineDialerEnv, "true")
	if got, want := enableAppEngineDialer(), true; got != want {
		t.Fatalf("expected enableAppEngineDialer to be true")
	}

	// Set the environment var to true, with a mix of upper and lower cases
	os.Setenv(enableAppEngineDialerEnv, "True")
	if got, want := enableAppEngineDialer(), true; got != want {
		t.Fatalf("expected enableAppEngineDialer to be true")
	}

	// Set the environment var to false
	os.Setenv(enableAppEngineDialerEnv, "false")
	if got, want := enableAppEngineDialer(), false; got != want {
		t.Fatalf("expected enableAppEngineDialer to be false")
	}

	// Set the environment var to something irrelevant
	os.Setenv(enableAppEngineDialerEnv, "something")
	if got, want := enableAppEngineDialer(), false; got != want {
		t.Fatalf("expected enableAppEngineDialer to be false")
	}
}
