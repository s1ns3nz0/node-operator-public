variable "foundation_network" {
  description = "Non-secret outputs from the separately owned foundation-network state."
  type = object({
    vpc_id                 = string
    system_subnet_ids      = list(string)
    hoodi_subnet_ids       = list(string)
    system_route_table_id  = string
    hoodi_route_table_id   = string
    hoodi_nat_gateway_id   = string
    hoodi_nat_public_ip    = string
  })

  validation {
    condition     = length(var.foundation_network.system_subnet_ids) >= 2 && length(var.foundation_network.hoodi_subnet_ids) >= 1
    error_message = "foundation_network must provide two system subnets and one Hoodi subnet."
  }
}
