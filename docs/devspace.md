# DevSpace Configuration

This project includes DevSpace configuration for Kubernetes development and deployment.

## Prerequisites

1. Install DevSpace CLI:
   ```bash
   # macOS
   brew install devspace

   # Or download from https://github.com/devspace-sh/devspace/releases
   ```

2. Ensure you have access to a Kubernetes cluster and `kubectl` is configured

## Quick Start

### Development Mode

Start development mode with hot reloading:

```bash
devspace dev
```

This will:
- Build the dev container image
- Deploy to Kubernetes
- Set up file synchronization
- Enable hot reloading with Air
- Forward ports (3001 for gRPC)
- Open a terminal in the container

This will take some time, you can follow progress in another terminal:

```bash
devspace logs -f
```

### Production Deployment

Deploy to production:

```bash
devspace deploy
```

## Available Commands

```bash
devspace list commands
```

```bash
# build images
devspace run build-images
# or
devspace build
```

```bash
# Quick build (run this only inside a container, unless you have all the dependencies installed locally)
devspace run compile
```

## Troubleshooting

### Kubernetes Context
Verify you're connected to the correct cluster:
```bash
kubectl config current-context
```

### DevSpace Logs
View DevSpace logs for debugging:
```bash
devspace logs
```

### Clean Up
Remove DevSpace deployment:
```bash
devspace purge
```
