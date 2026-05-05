package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	policyStore, err := policy.NewConfigMapStore(cfg)
	if err != nil {
		log.Fatalf("failed to create ConfigMap policy store: %v", err)
	}
	go func() {
		if err := policyStore.Run(ctx); err != nil {
			log.Printf("ConfigMap policy store stopped: %v", err)
		}
	}()

	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "3001"
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen on gRPC port %s: %v", grpcPort, err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(server.LoggingInterceptor()),
	)
	envoy_service_auth_v3.RegisterAuthorizationServer(grpcServer, server.NewAuthzGRPCServer(cfg, policyStore, exchange.NewClient(cfg, nil)))
	reflection.Register(grpcServer)

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("Starting gRPC ext_authz server on :%s", grpcPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
