package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/stats"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/exchange"
	"github.com/michaelw/ext-authz-token-exchange/internal/logging"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/server"
	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/filters"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const healthCheckMethod = "/grpc.health.v1.Health/Check"

func main() {
	logging.ConfigureStandard(os.Getenv("TOKEN_EXCHANGE_LOG_FORMAT"))
	if duration, ok, err := preStopSleepDuration(os.Args); ok {
		if err != nil {
			log.Fatal("invalid pre-stop sleep configuration: failure_class=configuration")
		}
		log.Printf("Sleeping %s for Kubernetes preStop drain", duration)
		time.Sleep(duration)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatal("invalid configuration: check runtime settings; TOKEN_EXCHANGE_LOG_FORMAT must be text or json")
	}
	apigeeCfg, err := config.LoadApigeeFromEnv()
	if err != nil {
		log.Fatal("invalid Apigee configuration: failure_class=configuration")
	}
	server.LogStartup(cfg, apigeeCfg.InspectMessages)
	if cfg.NeedsIssuerSecretResolution() {
		client, err := inClusterKubernetesClient()
		if err != nil {
			log.Fatal("failed to create Kubernetes client for issuer profile Secret resolution: failure_class=configuration")
		}
		cfg, err = config.ResolveIssuerProfileSecrets(ctx, client, podNamespaceFromEnv(), cfg)
		if err != nil {
			log.Fatal("invalid issuer profile Secret configuration: failure_class=configuration")
		}
	}

	shutdownTelemetry, err := telemetry.Init(ctx)
	if err != nil {
		log.Fatal("failed to initialize telemetry: failure_class=configuration")
	}
	defer func() {
		if err := shutdownTelemetry(context.Background()); err != nil {
			log.Print("failed to shut down telemetry: failure_class=internal")
		}
	}()

	policyStore, err := policy.NewConfigMapStore(cfg)
	if err != nil {
		log.Fatal("failed to create ConfigMap policy store: failure_class=configuration")
	}
	if err := policyStore.Start(ctx); err != nil {
		log.Fatal("failed to start ConfigMap policy store: failure_class=internal")
	}
	if cfg.MetricsEnabled {
		go serveMetrics(ctx, cfg)
	}

	errCh := make(chan error, 3)
	if apigeeCfg.Port != "" {
		go func() { errCh <- serveApigee(ctx, apigeeCfg, cfg, policyStore) }()
	}
	go func() {
		errCh <- serveGRPC(ctx, grpcPortFromEnv(), nil, cfg, policyStore)
	}()
	if tlsCfg, ok, err := grpcTLSConfigFromEnv(); err != nil {
		log.Fatal("invalid TLS gRPC configuration: failure_class=configuration")
	} else if ok {
		go func() {
			errCh <- serveGRPC(ctx, grpcTLSPortFromEnv(), tlsCfg, cfg, policyStore)
		}()
	}

	if err := <-errCh; err != nil {
		log.Fatal("gRPC server failed: failure_class=internal")
	}
}

type grpcTLSConfig struct {
	certFile string
	keyFile  string
}

func serveGRPC(ctx context.Context, port string, tlsCfg *grpcTLSConfig, cfg config.RuntimeConfig, policyStore policy.Store) error {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen on gRPC port %s: %w", port, err)
	}

	opts := []grpc.ServerOption{
		grpc.StatsHandler(grpcStatsHandler()),
		grpc.UnaryInterceptor(server.LoggingInterceptorWithOptions(loggingOptions(cfg))),
		grpc.StreamInterceptor(server.LoggingStreamInterceptorWithOptions(loggingOptions(cfg))),
	}
	if tlsCfg != nil {
		creds, err := credentials.NewServerTLSFromFile(tlsCfg.certFile, tlsCfg.keyFile)
		if err != nil {
			return fmt.Errorf("load gRPC TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(opts...)
	exchanger := exchange.NewClient(cfg, nil)
	envoy_service_auth_v3.RegisterAuthorizationServer(grpcServer, server.NewAuthzGRPCServer(cfg, policyStore, exchanger))
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, server.NewExtProcGRPCServer(cfg, policyStore, exchanger))
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	reflection.Register(grpcServer)

	go func() {
		<-ctx.Done()
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
	}()

	if tlsCfg != nil {
		log.Printf("Starting TLS gRPC ext_authz server on :%s", port)
	} else {
		log.Printf("Starting gRPC ext_authz server on :%s", port)
	}
	if err := grpcServer.Serve(lis); err != nil {
		return err
	}
	return nil
}

func inClusterKubernetesClient() (kubernetes.Interface, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(restConfig)
}

func podNamespaceFromEnv() string {
	return strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
}

func loggingOptions(cfg config.RuntimeConfig) server.LoggingOptions {
	methods := server.AuthzLoggingMethods()
	for method, logging := range server.ExtProcLoggingMethods() {
		methods[method] = logging
	}
	methods[healthCheckMethod] = server.LoggingMethod{
		LogEnabled:        cfg.LogHealthChecks,
		SummarizeResponse: summarizeHealthResponse,
	}
	return server.LoggingOptions{Format: cfg.LogFormat, Methods: methods}
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

func grpcTLSPortFromEnv() string {
	grpcTLSPort := os.Getenv("GRPC_TLS_PORT")
	if grpcTLSPort == "" {
		return "3000"
	}
	return grpcTLSPort
}

func grpcTLSConfigFromEnv() (*grpcTLSConfig, bool, error) {
	certFile := strings.TrimSpace(os.Getenv("GRPC_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("GRPC_TLS_KEY_FILE"))
	switch {
	case certFile == "" && keyFile == "":
		return nil, false, nil
	case certFile == "":
		return nil, false, fmt.Errorf("GRPC_TLS_CERT_FILE is required when GRPC_TLS_KEY_FILE is set")
	case keyFile == "":
		return nil, false, fmt.Errorf("GRPC_TLS_KEY_FILE is required when GRPC_TLS_CERT_FILE is set")
	default:
		return &grpcTLSConfig{certFile: certFile, keyFile: keyFile}, true, nil
	}
}

func preStopSleepDuration(args []string) (time.Duration, bool, error) {
	if len(args) < 2 || args[1] != "pre-stop-sleep" {
		return 0, false, nil
	}
	if len(args) == 2 {
		return 30 * time.Second, true, nil
	}
	duration, err := time.ParseDuration(args[2])
	if err != nil {
		return 0, true, err
	}
	return duration, true, nil
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
			log.Print("metrics server shutdown failed: failure_class=internal")
		}
	}()
	log.Printf("Starting Prometheus metrics server on :%s%s", cfg.MetricsPort, cfg.MetricsPath)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Print("metrics server failed: failure_class=internal")
	}
}
