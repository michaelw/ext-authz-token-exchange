name: ${GKE_AUTHZ_NAME}
authority: ${GATEWAY_EXT_AUTHZ_SERVICE_NAME}.${GKE_AUTHZ_CALLOUT_NAMESPACE}.svc.cluster.local
loadBalancingScheme: ${GKE_AUTHZ_LB_SCHEME}
service: ${CALLOUT_BACKEND_SERVICE_URI}
forwardHeaders:
  - authorization
  - cookie
  - origin
  - access-control-request-method
  - access-control-request-headers
  - x-request-id
  - traceparent
  - tracestate
failOpen: false
timeout: "1s"
wireFormat: EXT_AUTHZ_GRPC
