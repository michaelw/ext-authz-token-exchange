package logging

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestJSONAndLegacyRendering(t *testing.T) {
	var out bytes.Buffer
	l := log.New(&out, "[gRPC] ", log.LstdFlags)
	Write(l, "text", Event{}, "legacy | layout")
	if !strings.HasPrefix(out.String(), "[gRPC] ") || !strings.Contains(out.String(), "legacy | layout") {
		t.Fatal(out.String())
	}
	out.Reset()
	Write(l, "", Event{Name: "request_decision", Severity: "INFO", Message: Bound(strings.Repeat("x", 2000))}, "not JSON")
	var event Event
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if len(event.Message) > 530 || !strings.HasSuffix(event.Timestamp, "Z") {
		t.Fatal("unbounded message or non-UTC timestamp")
	}
}

func TestRuntimeJSONDoesNotIncludeRawError(t *testing.T) {
	var out bytes.Buffer
	w := runtimeWriter{out: &out}
	_, err := w.Write([]byte("gRPC server failed: https://ERROR_CANARY?secret=SECRET_CANARY\n"))
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "CANARY") || event.Severity != "ERROR" {
		t.Fatal(out.String())
	}
}

func TestStandardJSONNormalizesConfigurationWhitespace(t *testing.T) {
	writer, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() { log.SetOutput(writer); log.SetFlags(flags); log.SetPrefix(prefix) })
	var out bytes.Buffer
	log.SetOutput(&out)
	ConfigureStandard(" ")
	log.Print("gRPC server failed: failure_class=internal")
	var event Event
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
}
