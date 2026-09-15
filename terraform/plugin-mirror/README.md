# Offline provider mirror contract

The PR gate passes this directory as `TERRAFORM_PLUGIN_MIRROR`. When Terraform
modules are introduced, their providers must be added here from a reviewed,
checksum-verified source and locked in `.terraform.lock.hcl`. The collector
disables Terraform's direct installer, so an absent or incomplete mirror blocks
the gate rather than reaching the provider registry.
