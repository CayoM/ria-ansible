terraform {
  required_providers {
    instana = {
      source = "instana/instana"
      version = "5.1.1"
    }
  }
}

provider "instana" {
  api_token = var.instana_api_token
  endpoint = var.instana_endpoint
  tls_skip_verify     = var.instana_tls_skip_verify
}

resource "instana_application_config" "my_app" {
  label               = var.project_name
  scope               = var.instana_app_scope  #Optional, default = INCLUDE_NO_DOWNSTREAM
  boundary_scope      = var.instana_app_boundary_scope  #Optional, default = INBOUND
  tag_filter = var.instana_query
}