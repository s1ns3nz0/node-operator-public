terraform {
  # The verified release orchestrator derives this from bootstrap-state. A
  # baseline source tree must never bind a fresh deployment to another
  # account's historical state bucket or key.
  backend "s3" {}
}
