terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google      = { source = "hashicorp/google", version = "8.10.0" }
    google-beta = { source = "hashicorp/google-beta", version = "8.10.0" }
  }
}

variable "project_id" { type = string }
variable "region" { type = string }
variable "network" { type = string }
variable "psc_cidrs" { type = map(string) }

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "apigee" {
  for_each           = toset(["apigee.googleapis.com", "cloudkms.googleapis.com", "orgpolicy.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "proxy" {
  account_id   = "apigee-callout-proxy"
  display_name = "Identity for the development Apigee ExternalCallout proxy"
  depends_on   = [google_project_service.apigee]
}

resource "google_project_service_identity" "apigee" {
  provider   = google-beta
  project    = var.project_id
  service    = "apigee.googleapis.com"
  depends_on = [google_project_service.apigee]
}

resource "google_service_account_iam_member" "signer" {
  service_account_id = google_service_account.proxy.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_project_service_identity.apigee.email}"
}

resource "google_compute_subnetwork" "psc" {
  for_each      = var.psc_cidrs
  name          = "apigee-psc-${each.key}"
  region        = var.region
  network       = var.network
  purpose       = "PRIVATE_SERVICE_CONNECT"
  ip_cidr_range = each.value
}

output "proxy_service_account" { value = google_service_account.proxy.email }
output "proxy_subject" { value = google_service_account.proxy.unique_id }
output "psc_nat_subnets" { value = { for role, subnet in google_compute_subnetwork.psc : role => subnet.id } }
