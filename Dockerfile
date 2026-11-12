# syntax=docker/dockerfile:1.28

# match relative path from the root of the repository
ARG WORKSPACE=/workspaces/ext-authz-token-exchange
ARG USER=devuser
ARG USER_ID=1000
ARG GROUP_ID=1000

FROM hashicorp/terraform:1.15.5 AS terraform-tool

# Base stage
FROM golang:1.27.3-bookworm AS base
ARG WORKSPACE
ARG USER
ARG USER_ID
ARG GROUP_ID

USER root

RUN addgroup --gid ${GROUP_ID} ${USER} \
    && adduser --disabled-password --gecos "" --uid ${USER_ID} --gid ${GROUP_ID} ${USER} \
    && adduser ${USER} sudo

# Shared compiler and check tools. No source or cloud credentials in this stage.
FROM base AS toolchain
ARG TARGETARCH
ARG WORKSPACE
ARG USER
ARG USER_ID
ARG GROUP_ID
ARG HELM_VERSION=v4.1.1
ARG HELM_UNITTEST_VERSION=1.2.1
ARG PROTOC_VERSION=35.0
ARG YQ_VERSION=v4.46.1
ARG DEVSPACE_VERSION=v6.3.15

WORKDIR /tmp
COPY --from=terraform-tool /bin/terraform /usr/local/bin/terraform
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git unzip python3 python3-venv nodejs \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/checks \
    && /opt/checks/bin/pip install --no-cache-dir pre-commit==4.5.1
ENV PATH=/opt/checks/bin:$PATH
ENV HELM_PLUGINS=/opt/helm/plugins
ENV HELM_DATA_HOME=/opt/helm
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) protoarch=x86_64; protosha=a45cda0989c17dd950db55f6fbe1e5814c50fda08e87aa422980ac1f89dddbbc; helmsha=5d4c7623283e6dfb1971957f4b755468ab64917066a8567dd50464af298f4031 ;; \
      arm64) protoarch=aarch_64; protosha=36b518ac14d90351cc6598228ed2bbe5afe4e357b1af470b07e0ec1609875de2; helmsha=02a5fb7742469d2d132e24cb7c3f52885894043576588c6788b6813297629edd ;; \
      *) echo 'Unsupported tooling architecture' >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${protoarch}.zip" -o protoc.zip; \
    echo "$protosha  protoc.zip" | sha256sum -c -; \
    unzip -q protoc.zip -d /usr/local; rm protoc.zip; \
    curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz" -o helm.tar.gz; \
    echo "$helmsha  helm.tar.gz" | sha256sum -c -; \
    tar -xzf helm.tar.gz; install -m 0755 "linux-${TARGETARCH}/helm" /usr/local/bin/helm; \
    rm -rf helm.tar.gz "linux-${TARGETARCH}"
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12 \
    && GOBIN=/usr/local/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
# The plugin archive is checksum-verified before installation; no unpinned install hook.
RUN curl -fsSL "https://github.com/helm-unittest/helm-unittest/releases/download/v${HELM_UNITTEST_VERSION}/unittest-${HELM_UNITTEST_VERSION}.tgz" -o unittest.tgz \
    && echo 'bbcebd42631dff9fc595462fad839c49a1b06f9635e952e7e837d7e5fe82865f  unittest.tgz' | sha256sum -c - \
    && helm plugin install /tmp/unittest.tgz --verify=false \
    && rm unittest.tgz \
    && chmod -R a+rX /opt/helm
RUN mkdir -p /go-cache /artifacts "${WORKSPACE}" \
    && chown -R ${USER_ID}:${GROUP_ID} /go-cache /artifacts "${WORKSPACE}"
ENV GOCACHE=/go-cache/build
ENV GOMODCACHE=/go-cache/mod
ENV GOPATH=/go-cache
ENV CGO_ENABLED=0
RUN curl -fsSL -o /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${TARGETARCH}" \
    && chmod 0755 /usr/local/bin/yq
RUN curl -fsSL -o /usr/local/bin/devspace "https://github.com/devspace-sh/devspace/releases/download/${DEVSPACE_VERSION}/devspace-linux-${TARGETARCH}" \
    && chmod 0755 /usr/local/bin/devspace
USER ${USER}
WORKDIR ${WORKSPACE}

# Dev stage
FROM toolchain AS dev
ARG TARGETOS
ARG TARGETARCH
ARG WORKSPACE
ARG USER
USER root
WORKDIR /tmp
RUN apt-get update && apt-get install -y --no-install-recommends sudo \
    && rm -rf /var/lib/apt/lists/*
RUN echo "${USER} ALL=(ALL) NOPASSWD:ALL" | tee -a /etc/sudoers

COPY scripts/docker-entrypoint.sh /entrypoint.sh

RUN mkdir -p /.devspace /usr/local/share/bash-completion/completions \
    && chown ${USER}:${USER} /.devspace /usr/local/bin

RUN devspace completion bash > /usr/local/share/bash-completion/completions/devspace

RUN helm completion bash > /usr/local/share/bash-completion/completions/helm
RUN --mount=type=cache,target=/go-cache/build \
    GOBIN=/usr/local/bin go install github.com/air-verse/air@v1.65.1 \
    && GOBIN=/usr/local/bin go install github.com/go-delve/delve/cmd/dlv@v1.26.3

USER ${USER}

ENV GOCACHE=/go-cache/build
ENV GOMODCACHE=/go-cache/mod
ENV CGO_ENABLED=0

WORKDIR ${WORKSPACE}

CMD ["sleep", "infinity"]

# Kind jobs retain their existing Helm/Kubernetes pins, but share Go/protoc.
FROM dev AS smoke-toolchain
ARG TARGETARCH
USER root
ENV HELM_PLUGINS=/opt/smoke-helm/plugins
ENV HELM_DATA_HOME=/opt/smoke-helm
COPY --from=docker:29.5.2-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:29.5.2-cli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/lib/docker/cli-plugins/docker-buildx
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 make openssl netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://kind.sigs.k8s.io/dl/v0.29.0/kind-linux-${TARGETARCH}" -o /usr/local/bin/kind \
    && curl -fsSL "https://dl.k8s.io/release/v1.33.2/bin/linux/${TARGETARCH}/kubectl" -o /usr/local/bin/kubectl \
    && chmod 0755 /usr/local/bin/kind /usr/local/bin/kubectl \
    && curl -fsSL "https://get.helm.sh/helm-v3.18.3-linux-${TARGETARCH}.tar.gz" -o /tmp/helm.tar.gz \
    && tar -xzf /tmp/helm.tar.gz -C /tmp \
    && install -m 0755 "/tmp/linux-${TARGETARCH}/helm" /usr/local/bin/helm \
    && rm -rf /tmp/helm.tar.gz "/tmp/linux-${TARGETARCH}"
USER ${USER}

# Build stage
FROM toolchain AS build
ARG WORKSPACE
ARG USER
ARG USER_ID
ARG GROUP_ID

USER ${USER}

ENV GOCACHE=/go-cache/build
ENV GOMODCACHE=/go-cache/mod
ENV CGO_ENABLED=0

WORKDIR ${WORKSPACE}

COPY --chown=${USER}:${USER} go.mod go.sum ./
# Persist module downloads in a layer: cache mounts alone are not exported by GHA.
RUN go mod download
COPY --chown=${USER}:${USER} . .
RUN --mount=type=cache,target=/go-cache/build,uid=${USER_ID},gid=${GROUP_ID} \
    go generate ./... && go build -o bin/ -v ./cmd/...

# Run stage
FROM gcr.io/distroless/static-debian12 AS prod
ARG WORKSPACE
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/michaelw/ext-authz-token-exchange
USER 65532:65532

WORKDIR /app
COPY --from=build ${WORKSPACE}/bin/ext-authz-token-exchange-service /app/ext-authz-token-exchange-service
COPY LICENSE /app/LICENSE
COPY api/apigee/README.md /app/APIGEE-PROVENANCE.md

LABEL org.opencontainers.image.title="ext-authz-token-exchange" \
      org.opencontainers.image.description="Envoy external authorization plugin for OAuth 2.0 token exchange" \
      org.opencontainers.image.vendor="MagneticFlux LLC" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

EXPOSE 3001

ENTRYPOINT ["/app/ext-authz-token-exchange-service"]

# E2E fake token endpoint image. Keep this separate from production.
FROM gcr.io/distroless/static-debian12 AS fake-token-endpoint
ARG WORKSPACE
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/michaelw/ext-authz-token-exchange
USER 65532:65532

WORKDIR /app
COPY --from=build ${WORKSPACE}/bin/fake-token-endpoint /app/fake-token-endpoint

LABEL org.opencontainers.image.title="ext-authz-token-exchange-fake-token-endpoint" \
      org.opencontainers.image.description="Fake OAuth token endpoint for ext-authz-token-exchange demos and e2e tests" \
      org.opencontainers.image.vendor="MagneticFlux LLC" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

EXPOSE 8080

ENTRYPOINT ["/app/fake-token-endpoint"]

# Local InferencePool e2e backend. This image is never published by DevSpace.
FROM gcr.io/distroless/static-debian12 AS inference-test-backend
ARG WORKSPACE
USER 65532:65532
WORKDIR /app
COPY --from=build ${WORKSPACE}/bin/inference-test-backend /app/inference-test-backend
EXPOSE 8000
ENTRYPOINT ["/app/inference-test-backend"]
