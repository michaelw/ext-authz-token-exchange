# Ext AuthZ Token Exchange Plugin Development Guide

This document provides comprehensive development guidelines.

## 📋 Pull Request Rules

* Use [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/#specification) message format
  (`type` is `fix`, `feat`, `chore`, etc.)

  ```text
  <type>[optional scope in parenthesis]: <description>

  [optional body]

  [optional footer(s)]
  ```

  This helps with changelog generation.

---

## ⏱️ Development Phases

Follow these phases when implementing new features:

1. **Project Setup:** Generate the initial project structure and configuration files.
2. **gRPC Service:** Keep the Envoy ext-authz service wired and compilable.
3. **Business Logic:** Implement token exchange behavior in a modular way.
4. **Testing:** Write focused unit tests around authorization behavior.
5. **Polish and Harden:** Ensure the service is production-ready with proper error handling, logging, and documentation.
6. **Dev Environment:** Set up Docker Compose and VS Code DevContainer for development.

---

## 🐳 Development Environment

### Local Development

1. Start the development environment:
   ```bash
   devspace dev
   ```

2. The service will automatically reload on file changes thanks to `air`.

3. Access the gRPC service on port `3001` unless `GRPC_PORT` is configured.

---

## 🧪 Testing Strategy

### BDD Testing with Ginkgo + Gomega

* Use **Ginkgo** + **Gomega** for BDD-style tests
* All business logic must have unit tests
* Use **table-driven tests** (define struct above the test func)
* For Ginkgo tables, place the struct name on the same line as the Entry description

### Test Example

```go
Describe("FooHandler", func() {
  type testCase struct {
    input    string
    expected string
  }

  DescribeTable("does something",
    func(tc testCase) {
      ...
    },
    Entry("valid case", testCase{
      input: "bar",
      expected: "baz",
    }),
  )
})
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with Ginkgo
ginkgo -r

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## 🔧 Build and Deployment

### Building the Service

```bash
# Build all commands
go build ./cmd/...
```

---

## ⚠️ Important Constraints

* No schema migrations in the service itself
* Builds must be reproducible with `go build ./cmd/...`
* No unused or stub code — everything must be connected and testable
