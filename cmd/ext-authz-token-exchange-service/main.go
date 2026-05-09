package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/stats"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/server"
	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/filters"
)

const healthCheckMethod = "/grpc.health.v1.Health/Check"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	shutdownTelemetry, err := telemetry.Init(ctx)
	if err != nil {
		log.Fatalf("failed to initialize telemetry: %v", err)
	}
	defer func() {
		if err := shutdownTelemetry(context.Background()); err != nil {
			log.Printf("failed to shut down telemetry: %v", err)
		}
	}()

	policyStore, err := policy.NewConfigMapStore(cfg)
	if err != nil {
		log.Fatalf("failed to create ConfigMap policy store: %v", err)
	}
	go func() {
		if err := policyStore.Run(ctx); err != nil {
			log.Printf("ConfigMap policy store stopped: %v", err)
		}
	}()
	if cfg.MetricsEnabled {
		go serveMetrics(ctx, cfg)
	}

	grpcPort := grpcPortFromEnv()

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen on gRPC port %s: %v", grpcPort, err)
	}

	grpcServer := grpc.NewServer(
		grpc.StatsHandler(grpcStatsHandler()),
		grpc.UnaryInterceptor(server.LoggingInterceptorWithOptions(loggingOptions(cfg))),
	)
	envoy_service_auth_v3.RegisterAuthorizationServer(grpcServer, server.NewAuthzGRPCServer(cfg, policyStore, exchange.NewClient(cfg, nil)))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	reflection.Register(grpcServer)

	go func() {
		<-ctx.Done()
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
	}()

	log.Printf("Starting gRPC ext_authz server on :%s", grpcPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}

func loggingOptions(cfg config.RuntimeConfig) server.LoggingOptions {
	methods := server.AuthzLoggingMethods()
	methods[healthCheckMethod] = server.LoggingMethod{
		LogEnabled:        cfg.LogHealthChecks,
		SummarizeResponse: summarizeHealthResponse,
	}
	return server.LoggingOptions{Methods: methods}
}

func grpcStatsHandler() stats.Handler {
	return otelgrpc.NewServerHandler(
		otelgrpc.WithPropagators(telemetry.Propagators()),
		otelgrpc.WithFilter(grpcTracingFilter()),
	)
}

func grpcTracingFilter() otelgrpc.Filter {
	return filters.Not(filters.HealthCheck())
}

func summarizeHealthResponse(resp any) string {
	healthResp, ok := resp.(*healthpb.HealthCheckResponse)
	if !ok {
		return "unknown"
	}
	return "health_status=" + strings.ToLower(healthResp.GetStatus().String())
}

func grpcPortFromEnv() string {
	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		return "3001"
	}
	return grpcPort
}

func serveMetrics(ctx context.Context, cfg config.RuntimeConfig) {
	mux := http.NewServeMux()
	mux.Handle(cfg.MetricsPath, promhttp.Handler())
	server := &http.Server{
		Addr:    ":" + cfg.MetricsPort,
		Handler: mux,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("metrics server shutdown failed: %v", err)
		}
	}()
	log.Printf("Starting Prometheus metrics server on :%s%s", cfg.MetricsPort, cfg.MetricsPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("metrics server failed: %v", err)
	}
}
