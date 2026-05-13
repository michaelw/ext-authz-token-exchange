# syntax=docker/dockerfile:1.24

# match relative path from the root of the repository
ARG WORKSPACE=/workspaces/ext-authz-token-exchange
ARG USER=devuser

# Base stage
FROM golang:1.26.3-bookworm AS base
ARG WORKSPACE
ARG USER

USER root

RUN adduser --disabled-password --gecos "" ${USER} && adduser ${USER} sudo

# Dev stage
FROM base AS dev
ARG TARGETOS
ARG TARGETARCH
ARG WORKSPACE
ARG USER
ARG DEVSPACE_VERSION=v6.3.15
ARG HELM_VERSION=v3.18.4
ARG YQ_VERSION=v4.46.1

WORKDIR /tmp

RUN apt-get update && apt-get install -y \
    sudo curl git
RUN echo "${USER} ALL=(ALL) NOPASSWD:ALL" | tee -a /etc/sudoers

COPY scripts/docker-entrypoint.sh /entrypoint.sh

RUN mkdir -p /.devspace /usr/local/share/bash-completion/completions \
    && chown ${USER}:${USER} /.devspace /usr/local/bin

RUN curl -fsSL -o yq https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_${TARGETOS}_${TARGETARCH} \
    && install -c -m 0755 yq /usr/local/bin \
    && rm yq

RUN curl -fsSL -o devspace "https://github.com/devspace-sh/devspace/releases/download/${DEVSPACE_VERSION}/devspace-${TARGETOS}-${TARGETARCH}" \
    && install -c -m 0755 devspace /usr/local/bin \
    && rm devspace \
    && devspace completion bash > /usr/local/share/bash-completion/completions/devspace

RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \
    && chmod +x get_helm.sh \
    && ./get_helm.sh --version "${HELM_VERSION}" \
    && rm get_helm.sh \
    && helm completion bash > /usr/local/share/bash-completion/completions/helm

RUN --mount=type=cache,target=/go-cache \
    chown -v ${USER}:${USER} /go-cache

USER ${USER}

ENV GOCACHE=/go-cache/build
ENV GOMODCACHE=/go-cache/mod
ENV CGO_ENABLED=0

WORKDIR ${WORKSPACE}

CMD ["sleep", "infinity"]

# Build stage
FROM base AS build
ARG WORKSPACE
ARG USER

RUN --mount=type=cache,target=/go-cache \
    chown -v ${USER}:${USER} /go-cache

USER ${USER}

ENV GOCACHE=/go-cache/build
ENV GOMODCACHE=/go-cache/mod
ENV CGO_ENABLED=0

WORKDIR ${WORKSPACE}

COPY --chown=${USER}:${USER} go.mod go.sum ./
RUN --mount=type=cache,target=/go-cache \
    go mod download
COPY --chown=${USER}:${USER} . .
RUN --mount=type=cache,target=/go-cache \
    go build -o bin/ -v ./cmd/...

# Run stage
FROM gcr.io/distroless/static-debian12 AS prod
ARG WORKSPACE
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/michaelw/ext-authz-token-exchange
USER 65532:65532

WORKDIR /app
COPY --from=build ${WORKSPACE}/bin/ext-authz-token-exchange-service /app/ext-authz-token-exchange-service

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
