package main

import (
	"context"
	"fmt"
	"log"
	"net"

	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/server"
	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func serveApigee(ctx context.Context, c config.ApigeeConfig, cfg config.RuntimeConfig, store policy.Store) error {
	creds, err := credentials.NewServerTLSFromFile(c.CertFile, c.KeyFile)
	if err != nil {
		return fmt.Errorf("Apigee TLS: %w", err)
	}
	lis, err := net.Listen("tcp", ":"+c.Port)
	if err != nil {
		return fmt.Errorf("Apigee listen: %w", err)
	}
	defer lis.Close()
	loggingOptions := server.ApigeeLoggingOptions()
	loggingOptions.Format = cfg.LogFormat
	// Keep RPC metrics, but start the trace after decoding so payload-only
	// propagation does not create a second, unrelated transport-root span.
	stats := otelgrpc.NewServerHandler(otelgrpc.WithTracerProvider(noop.NewTracerProvider()), otelgrpc.WithPropagators(telemetry.Propagators()))
	srv := grpc.NewServer(grpc.Creds(creds), grpc.StatsHandler(stats), grpc.ChainUnaryInterceptor(
		server.LoggingInterceptorWithOptions(loggingOptions),
		server.ApigeeAuthentication(server.GoogleCalloutVerifier(ctx, c.Audience), c.AllowedSubjects),
		server.ApigeeTracing(),
	))
	pb.RegisterExternalCalloutServiceServer(srv, server.NewApigeeGRPCServer(cfg, store, exchange.NewClient(cfg, nil), c.InspectMessages))
	go func() { <-ctx.Done(); srv.GracefulStop() }()
	log.Printf("Starting authenticated Apigee ExternalCallout TLS server on :%s method=%s", c.Port, server.ApigeeProcessMethod)
	return srv.Serve(lis)
}
