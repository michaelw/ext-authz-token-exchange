# Ext AuthZ Token Exchange Plugin Implementation Guide

This document describes the architecture and technical decisions.

## 📁 Project Structure

The project follows the standard Go project layout and keeps runtime behavior
split across server, policy, exchange, and configuration packages:

```
.
├── internal/
│   ├── server/
│   │   ├── grpc_authz.go  # Envoy ext-authz decisions and responses
│   │   └── logging.go     # gRPC request logging interceptor
│   ├── policy/            # ConfigMap policy parsing and request matching
│   ├── exchange/          # RFC 8693 token exchange client
│   └── config/            # Runtime configuration parsing and validation
├── cmd/
│   └── ext-authz-token-exchange-service/
│       └── main.go        # Application bootstrap
├── charts/                # Helm charts for plugin and e2e/demo stack
├── devspace.yaml
├── Dockerfile
└── go.mod
```

## Technical Stack

* **Service API:** Envoy external authorization gRPC service
* **Transport:** `google.golang.org/grpc`
* **Generated API source:** Envoy protobufs from `github.com/envoyproxy/go-control-plane`
* **Policy source:** Kubernetes ConfigMaps selected by label and namespace selectors
* **Token exchange:** OAuth 2.0 Token Exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)

## 🎯 Design Principles

* **Idiomatic Go**: Follow effectivego.dev guidelines
* **Single Responsibility**: Each handler handles one resource type
* **Interface Segregation**: Define focused interfaces
* **Dependency Inversion**: Depend on abstractions, not concretions
* **Testability**: All business logic must be unit testable
