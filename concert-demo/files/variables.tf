variable "instana_api_token" {
  description = "Value of the Instana Api Token"
  type        = string
  default     = ""
}

variable "instana_endpoint" {
  description = "Value of the Instana Endpoint"
  type        = string
  default     = "ibmdevsandbox-instanaibm.instana.io"
}

variable "instana_tls_skip_verify" {
  description = "Skip TLS verification"
  type        = bool
  default     = false
}

variable "instana_app_scope" {
  description = "The scope of the application perspective"
  type        = string
  default     = "INCLUDE_ALL_DOWNSTREAM"
}

variable "instana_app_boundary_scope" {
  description = "The boundary scope of the application perspective"
  type        = string
  default     = "ALL"
}

variable "project_name" {
  description = "Name of the Project / Application"
  type        = string
  default     = "SUPER-AUTOMATION-DEMO"
}

variable "instana_query" {
  description = "Query to identify application among the OCP clusters"
  type        = string
  default     = ""
}