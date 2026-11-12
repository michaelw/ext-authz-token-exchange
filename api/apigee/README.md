# Apigee ExternalCallout protocol

`external_callout.proto` is an unmodified upstream file from
https://github.com/apigee/external-callout at commit
`8412b02c868bfed8fbfb6d4fc23f4311f68e956a`.

The service is unary `/apigee.ExternalCalloutService/ProcessMessage`.
The schema is authored by the upstream Apigee ExternalCallout contributors and
licensed under Apache-2.0. See the repository's root [LICENSE](../../LICENSE); the project's
copyright notice does not replace upstream authorship.

Go bindings are generated under `internal/apigeepb` and are not tracked.
Run `go generate ./...` in the shared tooling container before builds/tests.
Do not edit generated files. The Dockerfile pins the compiler and generators.

Google's policy documentation links this Go example:
https://github.com/srinandan/external-callout-samples/tree/main/hello-world-callout
It is reference material, not a runtime dependency or a supported Google product.
