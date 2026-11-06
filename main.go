// Command sigstore-kms-exoscalekms is a Sigstore KMS plugin for Exoscale KMS.
package main

import (
	"fmt"
	"os"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

func main() {
	pluginArgs, sv, err := load()
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		os.Exit(1)
	}
	if _, err := handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, sv); err != nil {
		os.Exit(1)
	}
}

func load() (*common.PluginArgs, *signerVerifier, error) {
	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		return nil, nil, err
	}
	if os.Args[1] != common.ProtocolVersion {
		return nil, nil, fmt.Errorf("unsupported protocol version %q, want %q", os.Args[1], common.ProtocolVersion)
	}
	endpoint, keyID, err := parseKeyRef(pluginArgs.InitOptions.KeyResourceID, os.Getenv("EXOSCALE_ZONE"))
	if err != nil {
		return nil, nil, err
	}
	if e := os.Getenv("EXOSCALE_API_ENDPOINT"); e != "" {
		endpoint = v3.Endpoint(e)
	}
	client, err := v3.NewClient(credentials.NewEnvCredentials(), v3.ClientOptWithEndpoint(endpoint))
	if err != nil {
		return nil, nil, fmt.Errorf("creating Exoscale client from EXOSCALE_API_KEY and EXOSCALE_API_SECRET: %w", err)
	}
	return pluginArgs, &signerVerifier{client: client, keyID: keyID}, nil
}
