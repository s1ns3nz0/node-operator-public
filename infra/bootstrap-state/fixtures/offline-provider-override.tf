# Copied to a disposable validation workspace as override.tf only. Never use
# this configuration for a live plan or apply.
provider "aws" {
  access_key                  = "offline"
  secret_key                  = "offline"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  allowed_account_ids         = []
}
