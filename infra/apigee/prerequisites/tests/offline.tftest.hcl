mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  project_id = "example-project"
  region     = "us-central1"
  network    = "projects/example-project/global/networks/development"
  psc_cidrs  = { callout = "10.50.0.0/24", backend = "10.51.0.0/24" }
}

run "dedicated_apigee_resources" {
  command = plan
  assert {
    condition     = !contains(keys(google_project_service.apigee), "compute.googleapis.com")
    error_message = "Compute API ownership must remain with generic infrastructure."
  }
  assert {
    condition     = length(google_compute_subnetwork.psc) == 2 && google_compute_subnetwork.psc["callout"].purpose == "PRIVATE_SERVICE_CONNECT"
    error_message = "Callout and backend require dedicated PSC NAT subnets."
  }
  assert {
    condition     = google_service_account.proxy.account_id == "apigee-callout-proxy"
    error_message = "Proxy identity must have a stable dedicated account name."
  }
}
