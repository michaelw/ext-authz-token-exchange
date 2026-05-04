# Ext AuthZ Token Exchange Plugin Implementation Guide

This document describes the architecture and technical decisions.

## 📁 Project Structure

The project follows the standard Go project layout:

```
.
├── internal/
│   └── server/
│       ├── grpc_authz.go  # Envoy ext-authz gRPC service stub
│       └── logging.go     # gRPC request logging interceptor
├── cmd/
│   └── ext-authz-token-exchange-service/
│       └── main.go        # Application bootstrap
├── devspace.yaml
├── Dockerfile
├── docker-compose.yml
├── .devcontainer/
│   └── devcontainer.json  # VS Code DevContainer setup
└── go.mod
```

## Technical Stack

* **Service API:** Envoy external authorization gRPC service
* **Transport:** `google.golang.org/grpc`
* **Generated API source:** Envoy protobufs from `github.com/envoyproxy/go-control-plane`

## 🎯 Design Principles

* **Idiomatic Go**: Follow effectivego.dev guidelines
* **Single Responsibility**: Each handler handles one resource type
* **Interface Segregation**: Define focused interfaces
* **Dependency Inversion**: Depend on abstractions, not concretions
* **Testability**: All business logic must be unit testable
