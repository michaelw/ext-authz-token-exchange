package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_ext_proc_config_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/michaelw/ext-authz-token-exchange/internal/config"
	"github.com/michaelw/ext-authz-token-exchange/internal/policy"
	"google.golang.org/protobuf/types/known/structpb"
)

const ExtProcProcessMethod = "/envoy.service.ext_proc.v3.ExternalProcessor/Process"

// ExtProcGRPCServer implements the Envoy external processing gRPC service.
type ExtProcGRPCServer struct {
	envoy_service_ext_proc_v3.UnimplementedExternalProcessorServer

	authz *AuthzGRPCServer
}

// NewExtProcGRPCServer creates a gRPC external processing server.
func NewExtProcGRPCServer(cfg config.RuntimeConfig, store policy.Store, exchanger tokenExchanger) *ExtProcGRPCServer {
	return &ExtProcGRPCServer{authz: NewAuthzGRPCServer(cfg, store, exchanger)}
}

// ExtProcLoggingMethods returns gRPC logging rules for the external processor.
func ExtProcLoggingMethods() map[string]LoggingMethod {
	return map[string]LoggingMethod{
		ExtProcProcessMethod: {
			LogEnabled:        true,
			SummarizeRequest:  summarizeExtProcRequest,
			SummarizeResponse: summarizeExtProcResponse,
		},
	}
}

func summarizeExtProcRequest(message any) string {
	req, ok := message.(*envoy_service_ext_proc_v3.ProcessingRequest)
	if !ok || req.GetRequestHeaders() == nil {
		return ""
	}
	values := extProcHeaders(req.GetRequestHeaders().GetHeaders())
	return fmt.Sprintf(" | %s | %s://%s%s",
		logField(extProcMethod(req, values)),
		logField(extProcScheme(req, values)),
		logField(extProcHost(req, values)),
		logPath(extProcPath(req, values)))
}

func summarizeExtProcResponse(message any) string {
	resp, ok := message.(*envoy_service_ext_proc_v3.ProcessingResponse)
	if !ok {
		return "unknown"
	}
	if resp.GetRequestHeaders() != nil {
		return "ok"
	}
	if immediate := resp.GetImmediateResponse(); immediate != nil && immediate.GetStatus() != nil {
		return "denied_status=" + logField(immediate.GetStatus().GetCode().String())
	}
	return "unknown"
}

// Process implements Envoy ext_proc request-header processing.
func (s *ExtProcGRPCServer) Process(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if req.GetObservabilityMode() {
			continue
		}

		resp := continueProcessingResponse(req)
		if headers := req.GetRequestHeaders(); headers != nil {
			resp = s.evaluateRequestHeaders(stream.Context(), req)
		}
		if resp == nil {
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (s *ExtProcGRPCServer) evaluateRequestHeaders(ctx context.Context, req *envoy_service_ext_proc_v3.ProcessingRequest) *envoy_service_ext_proc_v3.ProcessingResponse {
	values := extProcHeaders(req.GetRequestHeaders().GetHeaders())
	evaluation := s.authz.evaluateHTTPWithMetrics(ctx, httpEvaluationRequest{
		Method:  extProcMethod(req, values),
		Scheme:  extProcScheme(req, values),
		Host:    extProcHost(req, values),
		Path:    extProcPath(req, values),
		Headers: values,
	})
	if evaluation.Allowed {
		return extProcHeadersResponse(evaluation.Headers)
	}
	return extProcImmediateResponse(evaluation)
}

func extProcHeaders(headerMap *envoy_config_core_v3.HeaderMap) map[string]string {
	if headerMap == nil {
		return map[string]string{}
	}
	headers := make(map[string]string, len(headerMap.GetHeaders()))
	for _, headerValue := range headerMap.GetHeaders() {
		key := headerValue.GetKey()
		if key == "" {
			continue
		}
		value := headerValue.GetValue()
		if rawValue := headerValue.GetRawValue(); len(rawValue) > 0 {
			value = string(rawValue)
		}
		if existing, ok := headers[key]; ok && existing != "" && value != "" {
			headers[key] = existing + "," + value
			continue
		}
		headers[key] = value
	}
	return headers
}

func extProcMethod(req *envoy_service_ext_proc_v3.ProcessingRequest, headers map[string]string) string {
	if value := header(headers, ":method"); value != "" {
		return value
	}
	return extProcAttribute(req, "request.method")
}

func extProcScheme(req *envoy_service_ext_proc_v3.ProcessingRequest, headers map[string]string) string {
	if value := header(headers, ":scheme"); value != "" {
		return value
	}
	return extProcAttribute(req, "request.scheme")
}

func extProcHost(req *envoy_service_ext_proc_v3.ProcessingRequest, headers map[string]string) string {
	if value := header(headers, ":authority"); value != "" {
		return value
	}
	if value := header(headers, "host"); value != "" {
		return value
	}
	return extProcAttribute(req, "request.host")
}

func extProcPath(req *envoy_service_ext_proc_v3.ProcessingRequest, headers map[string]string) string {
	path := header(headers, ":path")
	if path == "" {
		path = extProcAttribute(req, "request.path")
		if query := extProcAttribute(req, "request.query"); path != "" && query != "" {
			path += "?" + query
		}
	}
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		if req, err := http.NewRequest(http.MethodGet, path, nil); err == nil {
			return req.URL.RequestURI()
		}
	}
	return path
}

func extProcAttribute(req *envoy_service_ext_proc_v3.ProcessingRequest, name string) string {
	if req == nil {
		return ""
	}
	return structString(req.GetAttributes()[name])
}

func structString(value *structpb.Struct) string {
	if value == nil {
		return ""
	}
	if field := stringValue(value.GetFields()["value"]); field != "" {
		return field
	}
	if field := stringValue(value.GetFields()["string_value"]); field != "" {
		return field
	}
	if field := stringValue(value.GetFields()["stringValue"]); field != "" {
		return field
	}
	if len(value.GetFields()) == 1 {
		for _, field := range value.GetFields() {
			return stringValue(field)
		}
	}
	return ""
}

func stringValue(value *structpb.Value) string {
	if value == nil {
		return ""
	}
	switch kind := value.GetKind().(type) {
	case *structpb.Value_StringValue:
		return kind.StringValue
	case *structpb.Value_NumberValue:
		return strings.TrimSuffix(strings.TrimSuffix(strconv.FormatFloat(kind.NumberValue, 'f', -1, 64), ".0"), ".")
	case *structpb.Value_BoolValue:
		if kind.BoolValue {
			return "true"
		}
		return "false"
	case *structpb.Value_StructValue:
		return structString(kind.StructValue)
	default:
		return ""
	}
}

func extProcHeadersResponse(headers []headerPair) *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status:          envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
					HeaderMutation:  extProcHeaderMutation(headers),
					ClearRouteCache: len(headers) > 0,
				},
			},
		},
		ModeOverride: requestHeadersOnlyMode(),
	}
}

func extProcImmediateResponse(evaluation httpEvaluation) *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
				Status:  &envoy_type_v3.HttpStatus{Code: envoyStatus(evaluation.Status)},
				Headers: extProcHeaderMutation(evaluation.Headers),
				Body:    []byte(evaluation.Body),
				Details: "ext_proc_token_exchange_denied",
			},
		},
	}
}

func extProcHeaderMutation(headers []headerPair) *envoy_service_ext_proc_v3.HeaderMutation {
	if len(headers) == 0 {
		return nil
	}
	return &envoy_service_ext_proc_v3.HeaderMutation{SetHeaders: rawHeaderOptions(headers)}
}

func continueProcessingResponse(req *envoy_service_ext_proc_v3.ProcessingRequest) *envoy_service_ext_proc_v3.ProcessingResponse {
	switch req.GetRequest().(type) {
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
		return extProcHeadersResponse(nil)
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
		return &envoy_service_ext_proc_v3.ProcessingResponse{
			Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
					Response: &envoy_service_ext_proc_v3.CommonResponse{Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE},
				},
			},
		}
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
		return &envoy_service_ext_proc_v3.ProcessingResponse{
			Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{
				RequestBody: &envoy_service_ext_proc_v3.BodyResponse{
					Response: &envoy_service_ext_proc_v3.CommonResponse{Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE},
				},
			},
		}
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseBody:
		return &envoy_service_ext_proc_v3.ProcessingResponse{
			Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseBody{
				ResponseBody: &envoy_service_ext_proc_v3.BodyResponse{
					Response: &envoy_service_ext_proc_v3.CommonResponse{Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE},
				},
			},
		}
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestTrailers:
		return &envoy_service_ext_proc_v3.ProcessingResponse{
			Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestTrailers{
				RequestTrailers: &envoy_service_ext_proc_v3.TrailersResponse{
					HeaderMutation: &envoy_service_ext_proc_v3.HeaderMutation{},
				},
			},
		}
	case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseTrailers:
		return &envoy_service_ext_proc_v3.ProcessingResponse{
			Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseTrailers{
				ResponseTrailers: &envoy_service_ext_proc_v3.TrailersResponse{
					HeaderMutation: &envoy_service_ext_proc_v3.HeaderMutation{},
				},
			},
		}
	default:
		return nil
	}
}

func requestHeadersOnlyMode() *envoy_ext_proc_config_v3.ProcessingMode {
	return &envoy_ext_proc_config_v3.ProcessingMode{
		RequestHeaderMode:   envoy_ext_proc_config_v3.ProcessingMode_SEND,
		ResponseHeaderMode:  envoy_ext_proc_config_v3.ProcessingMode_SKIP,
		RequestBodyMode:     envoy_ext_proc_config_v3.ProcessingMode_NONE,
		ResponseBodyMode:    envoy_ext_proc_config_v3.ProcessingMode_NONE,
		RequestTrailerMode:  envoy_ext_proc_config_v3.ProcessingMode_SKIP,
		ResponseTrailerMode: envoy_ext_proc_config_v3.ProcessingMode_SKIP,
	}
}
