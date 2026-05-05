# Repository Ground Rules

This file defines policy for agents and contributors working in this repository.
Use `DEVELOPMENT.md` for concrete setup, test, and release procedures.

## Git Commands

- Do not run git commands with side effects concurrently against this working
  tree. Execute them sequentially, or use separate git worktrees for parallel
  work.
- Before any side-effecting git command, inspect the repo state from inside this
  repo and stop if it is mid-merge, mid-rebase, locked, or otherwise in an
  unexpected conflict state.
- Do not mix unrelated changes in one commit.
- Keep feature commits separate from release, version-bump, image-tag, and chart
  packaging commits.
- Prefer Conventional Commit messages, for example `fix(server): reject invalid
  bearer headers`.

## Agent Coordination

- Only one agent may mutate this checkout at a time.
- If parallel implementation is required, give each agent a separate git
  worktree and a clearly scoped ownership area.
- Never revert or overwrite changes you did not make unless the user explicitly
  asks for it.
- Keep changes tightly scoped to the requested behavior and the packages it
  actually touches.

## Go Project Standards

- This is a Go module. Prefer `go test ./...`, `go test ./path/to/pkg`, and
  `go build ./cmd/...` over ad hoc build commands.
- Run `gofmt` on changed Go files. Use `go mod tidy` only when imports or module
  requirements intentionally changed.
- Keep package boundaries clear:
  - `cmd/` contains entrypoints and wiring.
  - `internal/config` owns runtime configuration parsing and defaults.
  - `internal/policy` owns policy parsing, validation, and indexing.
  - `internal/exchange` owns token exchange behavior.
  - `internal/server` owns Envoy ext-authz request/response behavior.
- Prefer small interfaces at package boundaries when they make tests clearer;
  avoid adding abstractions that do not remove concrete complexity.
- Pass `context.Context` through I/O paths and honor cancellation where practical.
- Return errors with useful context, but do not log secrets, bearer tokens, client
  secrets, or exchanged access tokens.

## Testing Policy

- Prefer TDD-style verification when practical: add or update a failing test
  first, confirm it fails on the pre-change behavior, then implement the fix and
  rerun the targeted tests.
- Use Ginkgo and Gomega for behavior tests in the existing style.
- Prefer table-driven tests for variants, edge cases, and validation matrices.
- Cover security-sensitive behavior directly: authorization decisions, fail-closed
  policy regions, header rewriting, OAuth error mapping, token endpoint auth, and
  namespace/policy selection.
- Unit tests should not require a Kubernetes cluster, network access, registry
  access, or local secrets.
- Run e2e tests only when the required local cluster, Gateway/Istio
  infrastructure, images, and chart deployment are available.

## Kubernetes, Helm, and DevSpace

- Prefer the documented DevSpace commands in `DEVELOPMENT.md` over hand-written
  deployment flows.
- Keep production chart changes and e2e chart changes intentionally separated.
- When changing chart templates, render or deploy the affected profile before
  considering the work verified.
- Do not commit generated cluster state, kubeconfigs, local registry credentials,
  or environment files.
- Keep image names, tags, and release metadata changes deliberate; do not sneak
  them into unrelated feature commits.

## Security and Compatibility

- Treat this service as fail-closed for matched but unhealthy policy regions.
- Do not weaken bearer-token handling, Envoy ext-authz response semantics, or
  OAuth token exchange validation without tests and documentation updates.
- Preserve compatibility behavior documented in `COMPATIBILITY.md`.
- Default to explicit allow-lists and validated configuration for policy inputs.
- Never commit absolute paths that point into a user's home directory or other
  machine-local paths. Prefer repo-relative paths in committed files.

## Documentation

- Update `README.md`, `DEVELOPMENT.md`, `COMPATIBILITY.md`, or files under
  `docs/` when behavior, setup, commands, or compatibility guarantees change.
- Keep documentation executable where possible: commands should be copy-pasteable
  from the repository root unless stated otherwise.
- Prefer concise, current docs over preserving stale TODOs.
