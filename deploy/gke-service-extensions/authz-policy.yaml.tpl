name: ${GKE_AUTHZ_NAME}
target:
  loadBalancingScheme: ${GKE_AUTHZ_LB_SCHEME}
  resources:
${GATEWAY_FORWARDING_RULE_RESOURCES}
policyProfile: REQUEST_AUTHZ
httpRules:
  - to:
      operations:
        - hosts:
            - exact: "${GKE_AUTHZ_HOST}"
          paths:
            - prefix: "/"
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - projects/${GKE_PROJECT_ID}/locations/${GKE_REGION}/authzExtensions/${GKE_AUTHZ_NAME}
