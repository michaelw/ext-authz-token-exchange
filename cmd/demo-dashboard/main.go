package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/michaelw/ext-authz-token-exchange/internal/demo"
)

//go:embed static
var staticFiles embed.FS

const defaultAddr = "127.0.0.1:8088"

type server struct {
	opts demo.Options
}

func main() {
	opts := demo.LoadOptionsFromEnv()
	addr := envDefault("DEMO_DASHBOARD_ADDR", defaultAddr)

	s := &server{opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", s.health)
	mux.HandleFunc("GET /api/scenarios", s.scenarios)
	mux.HandleFunc("POST /api/scenarios/run-all", s.runAll)
	mux.HandleFunc("POST /api/scenarios/{name}/run", s.runOne)
	mux.HandleFunc("GET /api/policies/{namespace}/{name}", s.policy)
	mux.HandleFunc("GET /api/logs/{component}", s.logs)
	mux.Handle("/", staticHandler())

	log.Printf("demo dashboard listening on http://%s", addr)
	log.Printf("using gateway %s and scenario config %s", opts.BaseURL, opts.ConfigPath)
	if err := http.ListenAndServe(addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) scenarios(w http.ResponseWriter, _ *http.Request) {
	cfg, err := demo.LoadConfig(s.opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for i := range cfg.Scenarios {
		cfg.Scenarios[i] = cfg.Scenarios[i].WithDefaults()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"baseURL":         s.opts.WithDefaults().BaseURL,
		"namespacePrefix": s.opts.WithDefaults().NamespacePrefix,
		"systemNamespace": s.opts.WithDefaults().SystemNamespace,
		"scenarios":       cfg.Scenarios,
	})
}

func (s *server) runOne(w http.ResponseWriter, r *http.Request) {
	cfg, err := demo.LoadConfig(s.opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sc, ok := cfg.Find(r.PathValue("name"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown scenario %q", r.PathValue("name")))
		return
	}
	result, _ := demo.Run(r.Context(), s.opts, sc)
	status := http.StatusOK
	if !result.Passed {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, result)
}

func (s *server) runAll(w http.ResponseWriter, r *http.Request) {
	cfg, err := demo.LoadConfig(s.opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	results := make([]demo.Result, 0, len(cfg.Scenarios))
	failed := 0
	for _, sc := range cfg.Scenarios {
		ctx, cancel := context.WithTimeout(r.Context(), demo.DefaultRequestTimeout+time.Second)
		result, _ := demo.Run(ctx, s.opts, sc)
		cancel()
		if !result.Passed {
			failed++
		}
		results = append(results, result)
	}
	status := http.StatusOK
	if failed > 0 {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]any{"failed": failed, "results": results})
}

func (s *server) policy(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")
	if !validKubernetesName(namespace) || !validKubernetesName(name) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid policy reference %q/%q", namespace, name))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "get", "configmap", "-n", namespace, name, "-o", "jsonpath={.data.config\\.yaml}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"namespace": namespace,
			"name":      name,
			"warning":   err.Error(),
			"text":      strings.TrimSpace(string(out)),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"namespace": namespace,
		"name":      name,
		"text":      string(out),
	})
}

func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	component := r.PathValue("component")
	deployment := ""
	switch component {
	case "plugin":
		deployment = "ext-authz-token-exchange-e2e"
	case "issuer":
		deployment = "fake-token-endpoint"
	default:
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown log component %q", component))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "logs", "-n", s.opts.WithDefaults().SystemNamespace, "deploy/"+deployment, "--tail=80")
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"component": component,
			"logs":      strings.TrimSpace(string(out)),
			"warning":   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"component": component, "logs": string(out)})
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func envDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func validKubernetesName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for i, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
		if !valid {
			return false
		}
		if (i == 0 || i == len(value)-1) && r == '-' {
			return false
		}
	}
	return true
}
