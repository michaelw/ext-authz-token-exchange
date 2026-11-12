terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = { source = "hashicorp/google", version = "8.10.0" }
  }
}

variable "project_id" { type = string }
variable "region" { type = string }
variable "network" { type = string }
variable "subnetwork" { type = string }
variable "apigee_service_attachment" { type = string }
variable "certificate_file" { type = string }
variable "private_key_file" { type = string }

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_region_network_endpoint_group" "apigee" {
  name                  = "devspace-apigee"
  region                = var.region
  network_endpoint_type = "PRIVATE_SERVICE_CONNECT"
  psc_target_service    = var.apigee_service_attachment
  network               = var.network
  subnetwork            = var.subnetwork
}

resource "google_compute_backend_service" "apigee" {
  name                  = "devspace-apigee"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  backend { group = google_compute_region_network_endpoint_group.apigee.id }
}

resource "google_compute_ssl_certificate" "apigee" {
  name_prefix = "devspace-apigee-"
  certificate = file(var.certificate_file)
  private_key = file(var.private_key_file)
  lifecycle { create_before_destroy = true }
}

resource "google_compute_url_map" "apigee" {
  name            = "devspace-apigee"
  default_service = google_compute_backend_service.apigee.id
}

resource "google_compute_target_https_proxy" "apigee" {
  name             = "devspace-apigee"
  url_map          = google_compute_url_map.apigee.id
  ssl_certificates = [google_compute_ssl_certificate.apigee.id]
}

resource "google_compute_global_address" "apigee" { name = "devspace-apigee" }

resource "google_compute_global_forwarding_rule" "apigee" {
  name                  = "devspace-apigee"
  ip_address            = google_compute_global_address.apigee.id
  target                = google_compute_target_https_proxy.apigee.id
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

output "ingress_address" { value = google_compute_global_address.apigee.address }
