// Package apigeepb contains bindings generated from the pinned Apigee schema.
package apigeepb

// Tools are pinned in the Dockerfile toolchain stage, not installed by generation.
//go:generate sh -c "test \"${DOLLAR}(protoc --version)\" = \"libprotoc 35.0\" || { echo 'protoc 35.0 is required' >&2; exit 1; }"
//go:generate protoc -I ../../api/apigee --go_out=. --go_opt=paths=source_relative --go_opt=Mexternal_callout.proto=github.com/michaelw/ext-authz-token-exchange/internal/apigeepb --go-grpc_out=. --go-grpc_opt=paths=source_relative --go-grpc_opt=Mexternal_callout.proto=github.com/michaelw/ext-authz-token-exchange/internal/apigeepb ../../api/apigee/external_callout.proto
