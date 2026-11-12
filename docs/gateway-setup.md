# Gateway Development Setup

See [production operations](operations.md) for supplied paid Apigee prerequisites,
TLS renewal, autoscaling, and trace continuity. See [gateway migration](gateway-migration.md)
for moving an existing application in either direction without moving cluster state.
Fresh Apigee setup defaults to evaluation when `--apigee` is omitted; saved modes
are retained. A positive development budget is still required for evaluation.

Run all commands from this repository. Install the tools listed in
DEVELOPMENT.md first. No project-specific host Go tools are required for the
dashboard or e2e binaries; the shared tooling image builds them.

Cloud lifecycle commands run on the host with Python 3, DevSpace, Docker, Git,
`yq`, Terraform, Helm, `gcloud`, `kubectl` with its GKE authentication plugin,
and OpenSSL on PATH. Authenticate `gcloud` and Application Default Credentials
before setup. Use the Terraform and Helm versions documented in DEVELOPMENT.md.
Containerized compilation and offline checks do not need cloud credentials;
the host lifecycle tools use your existing local credentials and kubeconfig.

## One Setup Command

Choose the Kubernetes and gateway lifecycles independently:

```sh
devspace run setup --gateway gke-gateway --infrastructure provision
devspace run setup --gateway apigee --infrastructure provision \
  --apigee evaluation --daily-budget 25
devspace run setup --gateway apigee --infrastructure existing \
  --apigee existing --inputs development-inputs.yaml
```

The two other Apigee combinations are `--infrastructure existing --apigee
evaluation` and `--infrastructure provision --apigee existing`. Evaluation
creation requires a positive daily budget. This records consent, not a billing
cap. No paid fallback or automatic expired-trial recreation is supported.

Setup resolves settings, checks the selected context, provisions only explicitly
selected infrastructure, deploys applications, configures the gateway, and runs
acceptance probes. Only successful probes produce the dashboard-ready message.

Settings and stage journals live under ignored `.devspace/`. Project and context
are resolved once and passed internally. A mismatch is an error. Ordinary daily
commands do not call infrastructure provisioning.

Provisioning refuses an unrelated active GKE context, because starter-pack
would otherwise select it as external infrastructure. Select a non-GKE context
before a new provisioned setup, or supply explicit existing-infrastructure inputs.

For cross-project setups, `project` identifies Kubernetes and `apigee_project`
identifies the Apigee management project. Inline Apigee settings inherit the
resolved context/region and the selected Apigee project. See the representative
input in `deploy/development-inputs.example.yaml`.

```sh
devspace dev
devspace deploy
devspace run test-e2e
devspace run demo-dashboard -- -open
devspace run diagnostics
devspace run log-format --format text
devspace run log-format --format json
```

The dashboard stays on loopback. Dashboard and tests share private Keycloak
access and terminate their port forwards on exit. Stop active processes with
Ctrl-C; `devspace run stop` restores development-replaced pods. Deployed Helm
releases, Apigee proxies, and infrastructure remain.

## Existing Infrastructure Inputs

Use one ignored YAML or JSON file. For an existing prepared Apigee application:

```yaml
project: example-project
region: us-central1
context: gke_example-project_us-central1_example-cluster
registry: us-central1-docker.pkg.dev/example-project/development
apigee_config: .devspace/apigee.json
```

`apigee_config` may instead be an inline object with the same structure as the
Apigee configuration described in [Apigee development](apigee.md). This permits
a single supplied input file. Reference certificates and keys by file path;
never embed credential values. Supply Helm values and their existing ownership
records when reconstructing a previously managed application.

The Apigee configuration identifies organization/environment, a dedicated
`txe-` proxy, deployment service account, callout/backend TLS endpoints,
Kubernetes release/namespaces, fixture values, and ingress trust. Set
`manage_targets: false` and provide each target's `name` to reference supplied
TargetServers. Supplied endpoints use `private_active: true`; their connectivity
must already be established. Unowned resources are not adopted.

For GKE Gateway, supply `domain`, `namespace`, and `gateway_name`. Existing mode
defaults to referencing that gateway. Set `manage_gateway: true` only to create
a dedicated gateway; never select this for an existing shared gateway. The
development gateway uses a self-signed certificate stored in a Kubernetes
Secret; trust it explicitly for strict HTTPS clients. No public DNS delegation
is required for direct-address tests.

## Ownership

| Resources | Owner |
| --- | --- |
| Generic project, GKE, VPC, registry | Starter-pack Terraform |
| Supplied pre-existing infrastructure | Its existing owner and Terraform state |
| New Apigee APIs, identity, PSC subnets, ingress | `infra/apigee/` in this repository |
| Evaluation organization and generated resources | Resumable Apigee provisioning stage |
| Plugin, fixtures, Services, ServiceAttachments | Helm through root DevSpace |
| Proxy revisions, targets, truststores, endpoint attachments | Apigee management helper |

Provisioned Kubernetes uses a pinned starter-pack checkout under
`.devspace/starter-pack`, or `--starter-pack PATH` for an explicit checkout.
The latter keeps its Terraform state in place. Setup invokes the documented
`ensure-cluster` command and reads structured Terraform outputs automatically.
It does not invoke starter-pack Apigee scripts or enable new Apigee components
there. New setups require no starter-pack source changes. Generic Terraform
state stays with the selected starter-pack checkout, not the Apigee modules.

Apigee-only Terraform state lives in `.devspace/apigee-infra/`. Protect this
directory: Terraform TLS certificate state contains private key material.
Input JSON contains references, not key contents. Keep the state and certificate
files out of version control and shared evidence.

## Recovery and Cleanup

Rerun the same setup command to inspect readiness and resume stages. Failed
stages remain recorded. A lost proxy-import response is reconciled only when
one new revision matches the requested bundle. Ambiguity stops the operation;
it does not cause another import. A failed deployment restores the previous
known-good revision. Keep ownership files when moving to another workstation.

Source-derived image tags remain stable while source content is unchanged.
Keycloak restarts for realm content changes, not every Helm revision. Changing
the selected target requires a separate workspace; setup must not reuse another
target's infrastructure journal or Terraform state.

```sh
# Explicitly undeploy one locally recorded revision.
devspace run undeploy-proxy --confirm-resource txe-example --revision 7
# Destructive: delete the dedicated proxy and its recorded API resources.
devspace run delete-proxy-resources --confirm-resource txe-example
# Removes disposable Helm fixtures only after PSC consumers are gone.
devspace run cleanup-fixtures
```

Ordinary Apigee purge only stops development. It never undeploys the proxy or
destroys cloud infrastructure. Infrastructure destruction is a separate action
against the original owner's state. Remove endpoint attachments before producer
ServiceAttachments, load balancers, and NAT subnets. Never destroy the original
starter-pack state as part of application cleanup.

`devspace run destroy-infrastructure --scope apigee --confirm-project PROJECT`
destroys only this repository's recorded Terraform resources, after dependency
checks. `--scope kubernetes` delegates to the recorded starter-pack checkout and
refuses supplied infrastructure. Neither command is part of deploy, tests, or
ordinary purge. The evaluation organization remains persistent until its own
explicit lifecycle or expiry.

For an entirely owned ephemeral evaluation, including its starter-pack project:

```sh
devspace run destroy-environment --confirm-project PROJECT
```

This separate command removes the owned proxy and consumer endpoint attachments,
purges Helm applications, waits for producer networking deletion, destroys
ingress, deletes the evaluation, and destroys Apigee prerequisites. It checks
component absence before asking starter-pack to destroy generic infrastructure
and shut down the project. Supplied infrastructure is refused. Interrupte

stages resume from an ignored journal; a successful teardown archives old
configuration and state under `.devspace/environments/PROJECT/` with restricted
permissions. Protect this archive because state contains private keys.

After teardown, the setup sequence at the start of this document creates a new
project through starter-pack and new Apigee resources through this repository.
Do not reuse the old project ID or copy archived ownership into the new setup.
Trial eligibility is checked by the provisioning request; refusal stops setup
without a paid fallback.

## Validation Gates

Offline tests cover setup-mode resolution, context/ownership checks, journals,
import recovery, rollback, chart fields, and shared behavior. CI never provisions
or deploys GCP resources.

Clean-local reconstruction, fresh application setup, and fresh cloud provisioning
are separate claims. Developer-run acceptance has exercised ownership transfer,
component cleanup and project shutdown, and fresh cloud/application setup through
the commands above. This does not authorize CI provisioning or destruction of
supplied infrastructure. See [validation evidence](apigee-validation.md).
