package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/s2a-go"
	"google.golang.org/api/option"
	"google.golang.org/appengine"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/oauth"

	translate "cloud.google.com/go/translate/apiv3"
	translatepb "cloud.google.com/go/translate/apiv3/translatepb"
)

const serverAddr = "translate.mtls.googleapis.com:443"

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx := appengine.NewContext(r)
	creds, err := s2a.NewClientCreds(&s2a.ClientOptions{S2AAddress: "metadata.google.internal:80"})
	if err != nil {
		errorMessage := "Failed to create S2A client credentials: %v" + err.Error()
		log.Fatalf("%v", errorMessage)
		http.Error(w, errorMessage, http.StatusBadRequest)
		return
	}
	perRPCCreds, err := oauth.NewApplicationDefault(ctx,
		"https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		errorMessage := "Failed to get per-RPC credentials: %v" + err.Error()
		log.Fatalf("%v", errorMessage)
		http.Error(w, errorMessage, http.StatusBadRequest)
		return
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(perRPCCreds),
		grpc.WithBlock(),
		grpc.WithReturnConnectionError(),
	}
	conn, err := grpc.DialContext(ctx, serverAddr, opts...)
	if err != nil {
		errorMessage := "Client: failed to connect: %v" + err.Error()
		log.Fatalf("%v", errorMessage)
		http.Error(w, errorMessage, http.StatusBadRequest)
		return
	}
	defer conn.Close()
	cliOpts := []option.ClientOption{option.WithGRPCConn(conn)}
	client, err := translate.NewTranslationClient(ctx, cliOpts...)
	if err != nil {
		errorMessage := "Failed to create client: %v" + err.Error()
		log.Fatalf("%v", errorMessage)
		http.Error(w, errorMessage, http.StatusBadRequest)
	}
	req := &translatepb.TranslateTextRequest{
		Contents:           []string{"Hello World!"},
		SourceLanguageCode: "en",
		TargetLanguageCode: "es",
		Parent:             fmt.Sprintf("projects/%s", os.Getenv("GOOGLE_CLOUD_PROJECT")),
	}
	_, err = client.TranslateText(ctx, req)
	if err != nil {
		errorMessage := "Failed to translate: %v" + err.Error()
		log.Fatalf("%v", errorMessage)
		http.Error(w, errorMessage, http.StatusBadRequest)
	}
	fmt.Fprintf(w, "success")
}

func main() {
	http.HandleFunc("/", indexHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	log.Printf("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
