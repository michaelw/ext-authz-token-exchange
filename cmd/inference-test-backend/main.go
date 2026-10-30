// Command inference-test-backend provides a CPU-only model server for local e2e tests.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

const model = "Qwen/Qwen3-32B"

type observation struct {
	Count         int    `json:"count"`
	Authorization string `json:"authorization"`
	Method        string `json:"method"`
	Path          string `json:"path"`
}

func main() {
	var mu sync.Mutex
	observed := map[string]observation{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte("vllm:num_requests_running{model_name=\"" + model + "\"} 0\n" +
			"vllm:num_requests_waiting{model_name=\"" + model + "\"} 0\n" +
			"vllm:kv_cache_usage_perc{model_name=\"" + model + "\"} 0\n" +
			"vllm:cache_config_info{block_size=\"16\",num_gpu_blocks=\"1024\"} 1\n" +
			"vllm:lora_requests_info{max_lora=\"1\",running_lora_adapters=\"\",waiting_lora_adapters=\"\"} 1\n"))
	})
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"Qwen/Qwen3-32B","object":"model"}]}`))
	})
	mux.HandleFunc("GET /observations", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		item := observed[r.URL.Query().Get("case")]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(item)
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Model != model {
			http.Error(w, "invalid test request", http.StatusBadRequest)
			return
		}
		caseID := r.Header.Get("X-Test-Case")
		mu.Lock()
		item := observed[caseID]
		item.Count++
		item.Authorization = r.Header.Get("Authorization")
		item.Method = r.Method
		item.Path = r.URL.Path
		observed[caseID] = item
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","object":"chat.completion","model":"Qwen/Qwen3-32B","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	})
	log.Fatal(http.ListenAndServe(":8000", mux))
}
