# Change Gateways Without Changing Policy Behavior

Use this procedure for GKE Gateway to managed Apigee, or the reverse. This is an
application/integration migration, not a cluster rebuild. Keep generic GKE,
network, registry, DNS, and Terraform ownership in starter-pack.

## Prepare

1. Record the current project, context, Helm releases, proxy revision, routes,
   hostnames, certificate issuers, and resource owners. Keep credentials out of
   this inventory. Retain the known-good image digest and configuration.
2. Prepare a separate checkout and ignored settings for the destination. Do not
   overwrite the source's `.devspace/gateway.json`, state, or ownership journals.
   Use the same reviewed source revision in both checkouts.
3. Reuse policy ConfigMaps and issuer profiles where appropriate. Secret
   references must exist in the destination plugin namespace; copy credentials
   through the operator's Secret delivery system, not tracked values files.
4. Review client-facing host/path matching and token audience/resource values.
   A new hostname can require policy and issuer changes even when paths stay the
   same. Do not substitute a backend hostname for original request identity.
5. Obtain approval before adding billable gateway/network resources. Do not
   create a second ephemeral environment merely to change gateway selection.

## GKE Gateway to Apigee

1. Supply an existing organization/environment, dedicated proxy identity, private
   callout/backend endpoints, explicit trust, and owned plugin values. See
   [operations](operations.md) and the production examples under `deploy/apigee/`.
2. In the destination checkout, run:

   ```sh
   devspace run setup --gateway apigee --infrastructure existing \
     --apigee existing --inputs development-inputs.yaml
   devspace deploy
   ```

3. Preserve existing shared gateways and networks. The new integration must not
   adopt them, install Envoy filters, or attach a second processor to the backend
   route. Apigee ExternalCallout makes one decision; the backend route must not
   invoke the old ext-proc/ext-authz integration again.
4. Validate the destination through a temporary operator-approved hostname or
   explicit address override with the real hostname and trusted CA. Do not
   disable certificate validation to test the destination.

## Apigee to GKE Gateway

1. Supply the existing cluster, registry, domain, gateway namespace/name, and
   certificate prerequisites. Set `manage_gateway: false` for a supplied Gateway.
   Creating a dedicated owned Gateway requires an explicit choice and cost review.
2. In the destination checkout, run:

   ```sh
   devspace run setup --gateway gke-gateway --infrastructure existing \
     --inputs development-inputs.yaml
   devspace deploy
   ```

3. Configure the selected GKE integration mode and its private/TLS callout path.
   Do not route back through the old Apigee token-exchange proxy. Preserve
   fail-closed timeout behavior and original client-facing host/path metadata.
4. Test through the destination address before changing client routing.

## Acceptance, Cutover, and Rollback

For synthetic development, run `devspace run test-e2e` and the dashboard. Existing
production setup runs only its configured unauthenticated acceptance probe; it
does not install demo fixtures or prove the full authorization contract. Run an
operator-approved synthetic test suite before switching real clients.

Verify successful exchange; missing, malformed, and duplicate bearer denial;
explicit deny; unmatched and unhealthy policies; CORS; OAuth/transport failures;
denial status/body/challenges; method/host/path/query/body preservation; and one
token exchange per matched request. Compare traces and latency without recording
tokens. Check issuer capacity and private reachability from the new plugin.

Change DNS, traffic weights, or client configuration through the existing
operator-controlled routing process. The setup commands do not make this cutover
for you. Keep the source ready during a defined rollback window. Roll back by
restoring routing, not by trying to reverse Terraform ownership.

After acceptance, remove only source resources recorded as owned. Undeploy a
dedicated Apigee proxy before deleting its configuration and endpoint attachments;
remove producer ServiceAttachments before their load balancers/subnets. Do not
use `destroy-environment` on shared or supplied infrastructure. Retain source
configuration and rollback evidence according to the operator's retention policy.
