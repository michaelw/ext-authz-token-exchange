// Package policy parses app-owned ConfigMaps and matches requests to token
// exchange policy entries.
package policy

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"gopkg.in/yaml.v3"
)

// Source identifies the Kubernetes object that provided policy.
type Source struct {
	Namespace string
	Name      string
}

// Entry is a validated app-owned token exchange policy entry.
type Entry struct {
	Source     Source
	Action     Action
	Host       string
	PathPrefix string
	Methods    []string
	Scope      string
	Resources  []string
	Audiences  []string
	IssuerRef  string
}

// Action describes what to do with a matched policy entry.
type Action string

const (
	// ActionExchange is the default action and preserves existing token exchange behavior.
	ActionExchange Action = "exchange"
	// ActionDeny intentionally rejects matched requests without token exchange.
	ActionDeny Action = "deny"
)

// Region is a host/path/method area that must fail closed because its policy
// source was invalid or ambiguous.
type Region struct {
	Source     Source
	Host       string
	PathPrefix string
	Methods    []string
	Reason     string
}

// Index is an immutable policy snapshot.
type Index struct {
	entries []Entry
	regions []Region
}

// Decision describes the result of matching an incoming request.
type Decision struct {
	Entry     Entry
	Matched   bool
	Unhealthy bool
	Reason    string
}

// EmptyIndex returns an immutable index with no configured policy.
func EmptyIndex() *Index {
	return &Index{}
}

type file struct {
	Version string     `yaml:"version"`
	Entries []rawEntry `yaml:"entries"`
}

type rawEntry struct {
	Match    *rawMatch    `yaml:"match"`
	Action   string       `yaml:"action"`
	Exchange *rawExchange `yaml:"exchange"`
}

type rawMatch struct {
	Host       string   `yaml:"host"`
	PathPrefix string   `yaml:"pathPrefix"`
	Methods    []string `yaml:"methods"`
}

type rawExchange struct {
	Scope     string   `yaml:"scope"`
	Resources []string `yaml:"resources"`
	Audiences []string `yaml:"audiences"`
	IssuerRef string   `yaml:"issuerRef"`
}

// BuildIndex parses all supplied ConfigMap payloads into a new immutable index.
func BuildIndex(items map[Source]string, cfg config.RuntimeConfig) *Index {
	var entries []Entry
	var regions []Region
	for source, data := range items {
		parsed, invalid := parseConfig(source, data, cfg)
		entries = append(entries, parsed...)
		regions = append(regions, invalid...)
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Host != entries[j].Host {
			return entries[i].Host < entries[j].Host
		}
		if entries[i].PathPrefix != entries[j].PathPrefix {
			return len(entries[i].PathPrefix) > len(entries[j].PathPrefix)
		}
		return strings.Join(entries[i].Methods, ",") < strings.Join(entries[j].Methods, ",")
	})
	return &Index{entries: entries, regions: regions}
}

// Match finds token exchange policy for a request.
func (i *Index) Match(host, path, method string) Decision {
	if i == nil {
		return Decision{}
	}
	host = normalizeHost(host)
	method = strings.ToUpper(method)

	for _, region := range i.regions {
		if region.matches(host, path, method) {
			return Decision{Matched: true, Unhealthy: true, Reason: region.Reason}
		}
	}

	var matches []Entry
	longest := -1
	for _, entry := range i.entries {
		if !entry.matches(host, path, method) {
			continue
		}
		prefixLen := len(entry.PathPrefix)
		if prefixLen > longest {
			longest = prefixLen
			matches = matches[:0]
		}
		if prefixLen == longest {
			matches = append(matches, entry)
		}
	}
	if len(matches) == 0 {
		return Decision{}
	}
	if len(matches) > 1 {
		return Decision{Matched: true, Unhealthy: true, Reason: "multiple policy entries tie for most-specific pathPrefix"}
	}
	return Decision{Matched: true, Entry: matches[0]}
}

func parseConfig(source Source, data string, cfg config.RuntimeConfig) ([]Entry, []Region) {
	var parsed file
	decoder := yaml.NewDecoder(bytes.NewReader([]byte(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return nil, []Region{{Source: source, Reason: fmt.Sprintf("config.yaml is not valid policy YAML: %v", err)}}
	}
	if parsed.Version != "v1" {
		return nil, []Region{{Source: source, Reason: "version must be v1"}}
	}

	var entries []Entry
	var regions []Region
	for idx, raw := range parsed.Entries {
		entry, region, ok := normalizeEntry(source, idx, raw, cfg)
		if ok {
			entries = append(entries, entry)
		} else {
			regions = append(regions, region)
		}
	}
	return entries, regions
}

func normalizeEntry(source Source, idx int, raw rawEntry, cfg config.RuntimeConfig) (Entry, Region, bool) {
	action := normalizeAction(raw.Action)
	var match rawMatch
	if raw.Match != nil {
		match = *raw.Match
	}
	region := Region{
		Source:     source,
		Host:       normalizeHost(match.Host),
		PathPrefix: normalizePathPrefix(match.PathPrefix),
		Methods:    normalizeMethods(match.Methods),
	}
	var problems []string
	if raw.Match == nil {
		problems = append(problems, entryPath(idx, "match")+" is required")
	}
	if region.Host == "" {
		problems = append(problems, entryPath(idx, "match.host")+" is required")
	}
	if region.PathPrefix == "" {
		problems = append(problems, entryPath(idx, "match.pathPrefix")+" is required")
	}
	if strings.TrimSpace(raw.Action) == "" {
		problems = append(problems, entryPath(idx, "action")+" is required")
	} else if action == "" {
		problems = append(problems, entryPath(idx, "action")+" must be exchange or deny")
	}
	if len(problems) > 0 {
		region.Reason = strings.Join(problems, "; ")
		return Entry{}, region, false
	}
	if action == ActionDeny {
		return Entry{
			Source:     source,
			Action:     action,
			Host:       region.Host,
			PathPrefix: region.PathPrefix,
			Methods:    region.Methods,
		}, Region{}, true
	}

	if raw.Exchange == nil {
		region.Reason = entryPath(idx, "exchange") + " is required when action is exchange"
		return Entry{}, region, false
	}

	exchange := *raw.Exchange
	resources := compact(exchange.Resources)
	// RFC8707 Section 2 defines resource as the target service URI.
	// https://www.rfc-editor.org/rfc/rfc8707#section-2
	audiences := compact(exchange.Audiences)
	if strings.TrimSpace(exchange.Scope) == "" && len(resources) == 0 && len(audiences) == 0 {
		problems = append(problems, entryPath(idx, "exchange")+" requires at least one of scope, resources, or audiences")
	}

	issuerRef := strings.TrimSpace(exchange.IssuerRef)
	if issuerRef == "" {
		problems = append(problems, entryPath(idx, "exchange.issuerRef")+" is required")
	} else if _, ok := cfg.IssuerProfile(issuerRef); !ok {
		problems = append(problems, fmt.Sprintf("%s references unknown issuer profile %q", entryPath(idx, "exchange.issuerRef"), issuerRef))
	}

	if len(problems) > 0 {
		region.Reason = strings.Join(problems, "; ")
		return Entry{}, region, false
	}
	return Entry{
		Source:     source,
		Action:     action,
		Host:       region.Host,
		PathPrefix: region.PathPrefix,
		Methods:    region.Methods,
		Scope:      strings.TrimSpace(exchange.Scope),
		Resources:  resources,
		Audiences:  audiences,
		IssuerRef:  issuerRef,
	}, Region{}, true
}

func normalizeAction(action string) Action {
	action = strings.ToLower(strings.TrimSpace(action))
	switch Action(action) {
	case ActionExchange, ActionDeny:
		return Action(action)
	default:
		return ""
	}
}

func entryPath(idx int, field string) string {
	return fmt.Sprintf("entries[%d].%s", idx, field)
}

func (e Entry) matches(host, path, method string) bool {
	return strings.EqualFold(e.Host, host) && strings.HasPrefix(path, e.PathPrefix) && methodAllowed(e.Methods, method)
}

func (r Region) matches(host, path, method string) bool {
	if r.Host != "" && !strings.EqualFold(r.Host, host) {
		return false
	}
	if r.PathPrefix != "" && !strings.HasPrefix(path, r.PathPrefix) {
		return false
	}
	return methodAllowed(r.Methods, method)
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if idx := strings.Index(host, ":"); idx > -1 {
		return host[:idx]
	}
	return host
}

func normalizePathPrefix(pathPrefix string) string {
	pathPrefix = strings.TrimSpace(pathPrefix)
	if pathPrefix == "" {
		return ""
	}
	if !strings.HasPrefix(pathPrefix, "/") {
		pathPrefix = "/" + pathPrefix
	}
	return pathPrefix
}

func normalizeMethods(methods []string) []string {
	if len(methods) == 0 {
		return []string{"*"}
	}
	out := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			out = append(out, method)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	sort.Strings(out)
	return out
}

func methodAllowed(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, allowed := range methods {
		if allowed == "*" || allowed == method {
			return true
		}
	}
	return false
}

func compact(values []string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
