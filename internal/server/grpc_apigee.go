package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	pb "github.com/michaelw/ext-authz-token-exchange/internal/apigeepb"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/logging"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"github.com/michaelw/ext-authz-token-exchange/internal/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const ApigeeProcessMethod = "/apigee.ExternalCalloutService/ProcessMessage"

func ApigeeLoggingOptions() LoggingOptions {
	return LoggingOptions{Methods: map[string]LoggingMethod{ApigeeProcessMethod: {
		LogEnabled: true,
		SummarizeRequest: func(value any) string {
			m, _ := value.(*pb.MessageContext)
			return " | message_id=" + safeCorrelation(m.GetMessageId())
		},
		SummarizeResponse: func(value any) string {
			m, _ := value.(*pb.MessageContext)
			return "decision=" + safeApigeeDecision(apigeeString(m, "txe.decision"))
		},
	}}}
}

// ApigeeGRPCServer adapts Apigee's message context to the common evaluator.
type ApigeeGRPCServer struct {
	pb.UnimplementedExternalCalloutServiceServer
	evaluator *requestEvaluator
	inspect   bool
	logFormat string
}

func NewApigeeGRPCServer(cfg config.RuntimeConfig, store policy.Store, exchanger tokenExchanger, inspect bool) *ApigeeGRPCServer {
	return &ApigeeGRPCServer{evaluator: newRequestEvaluator(cfg, store, exchanger), inspect: inspect, logFormat: cfg.LogFormat}
}

func (s *ApigeeGRPCServer) ProcessMessage(ctx context.Context, req *pb.MessageContext) (*pb.MessageContext, error) {
	if s.inspect {
		s.inspectMessage("request", req)
	}
	if req.GetRequest() == nil {
		return nil, status.Error(codes.InvalidArgument, "request flow required")
	}
	host := apigeeString(req, "txe.input.host")
	path := apigeeString(req, "txe.input.path")
	scheme := apigeeString(req, "txe.input.scheme")
	method := req.GetRequest().GetVerb()
	u, err := url.ParseRequestURI(path)
	if host == "" || method == "" || (scheme != "https" && scheme != "http") || err != nil || u.IsAbs() || !strings.HasPrefix(path, "/") {
		return nil, status.Error(codes.InvalidArgument, "trusted original request metadata required")
	}
	// Header names are case-insensitive. Merge variants deterministically so a
	// duplicate Authorization cannot be selected by map iteration order.
	headers := map[string]string{}
	keys := make([]string, 0, len(req.Request.Headers))
	for k := range req.Request.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := strings.ToLower(k)
		value := strings.Join(req.Request.Headers[k].GetStrings(), ",")
		if old, ok := headers[name]; ok {
			value = old + "," + value
		}
		headers[name] = value
	}
	evaluation := s.evaluator.evaluateHTTPWithMetrics(telemetry.RequestContext(ctx, headers), httpEvaluationRequest{Adapter: "apigee", GatewayID: req.GetMessageId(), ProxyRevision: req.GetApiProxy().GetRevision(), Method: method, Scheme: scheme, Host: host, Path: path, Headers: headers})
	resp := proto.Clone(req).(*pb.MessageContext)
	if resp.AdditionalFlowVariables == nil {
		resp.AdditionalFlowVariables = map[string]*pb.FlowVariable{}
	}
	decision := "deny"
	code := evaluation.Status
	if evaluation.Allowed {
		decision = "allow"
		code = http.StatusOK
		for _, h := range evaluation.Headers {
			for k := range resp.Request.Headers {
				if strings.EqualFold(k, h.Name) {
					delete(resp.Request.Headers, k)
				}
			}
			if resp.Request.Headers == nil {
				resp.Request.Headers = map[string]*pb.Strings{}
			}
			resp.Request.Headers[strings.ToLower(h.Name)] = &pb.Strings{Strings: []string{h.Value}}
		}
	}
	challenges := []string{}
	for _, h := range evaluation.Headers {
		if strings.EqualFold(h.Name, "WWW-Authenticate") {
			challenges = append(challenges, h.Value)
		}
	}
	resp.AdditionalFlowVariables["txe.decision"] = apigeeStringVariable(decision)
	resp.AdditionalFlowVariables["txe.status"] = &pb.FlowVariable{Value: &pb.FlowVariable_Int32{Int32: int32(code)}}
	resp.AdditionalFlowVariables["txe.body"] = apigeeStringVariable(evaluation.Body)
	resp.AdditionalFlowVariables["txe.www_authenticate"] = apigeeStringVariable(strings.Join(challenges, ", "))
	if s.inspect {
		mutated := []string{}
		if evaluation.Allowed {
			for _, header := range evaluation.Headers {
				mutated = append(mutated, logField(header.Name))
			}
		}
		shape := &logging.Shape{Direction: "mutation", MutationNames: mutated, ChallengeCount: len(challenges)}
		logging.Write(customLogger, s.logFormat, logging.Event{Name: "message_inspection", Severity: "DEBUG", Adapter: "apigee", Inspection: shape}, fmt.Sprintf("APIGEE_MUTATION decision=%s request_header_names=%v challenge_count=%d", decision, mutated, len(challenges)))
		s.inspectMessage("response", resp)
	}
	return resp, nil
}

func apigeeString(req *pb.MessageContext, name string) string {
	return req.GetAdditionalFlowVariables()[name].GetString_()
}
func apigeeStringVariable(value string) *pb.FlowVariable {
	return &pb.FlowVariable{Value: &pb.FlowVariable_String_{String_: value}}
}

// Inspection records the protobuf shape, not arbitrary message values.
func (s *ApigeeGRPCServer) inspectMessage(direction string, m *pb.MessageContext) {
	if m == nil {
		logging.Write(customLogger, s.logFormat, logging.Event{Name: "message_inspection", Severity: "DEBUG", Adapter: "apigee", Inspection: &logging.Shape{Direction: direction}}, "APIGEE_MESSAGE direction="+direction+" missing=true")
		return
	}
	fields := []string{}
	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		fields = append(fields, string(fd.Name()))
		return true
	})
	sort.Strings(fields)
	headers := map[string]int{}
	for name, values := range m.GetRequest().GetHeaders() {
		headers[safeHeaderName(name)] += len(values.GetStrings())
	}
	variables := map[string]string{}
	for name, value := range m.GetAdditionalFlowVariables() {
		switch name {
		case "txe.input.host", "txe.input.path", "txe.input.scheme", "txe.decision", "txe.status", "txe.body", "txe.www_authenticate":
		default:
			name = "[other]"
		}
		kind := "unset"
		value.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
			kind = string(fd.Name())
			return true
		})
		variables[name] = kind
	}
	shape := &logging.Shape{Direction: direction, Fields: fields, Headers: headers, Variables: variables}
	data, _ := json.Marshal(shape)
	logging.Write(customLogger, s.logFormat, logging.Event{Name: "message_inspection", Severity: "DEBUG", Adapter: "apigee", GatewayID: safeCorrelation(m.GetMessageId()), GatewayIDSource: "apigee_message_context", ProxyRevision: safeCorrelation(m.GetApiProxy().GetRevision()), Inspection: shape}, "APIGEE_MESSAGE direction="+direction+" shape="+string(data))
}

func safeApigeeDecision(value string) string {
	if value == "allow" || value == "deny" {
		return value
	}
	return "unset"
}
