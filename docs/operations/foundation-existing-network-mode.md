# Foundation existing-network mode

`network_mode = "fresh"` remains the default and creates the complete
foundation network. The accompanying `moved` blocks preserve prior fresh-mode
state addresses during the one-time upgrade to counted resources; a saved,
reviewed plan is required before using them with state.

`network_mode = "existing"` is an import-preparation configuration only. It
reads the baseline VPC, private subnets, private route table, and NAT public
subnet as data and verifies their VPC/CIDR relationship. It manages exactly
these public-edge addresses after separately approved imports:

- `aws_subnet.nat`
- `aws_eip.hoodi_nat`
- `aws_internet_gateway.nat`
- `aws_route_table.public`
- `aws_route_table_association.public`
- `aws_nat_gateway.hoodi`

It never manages the baseline VPC, private subnets, private route table, or
private associations. Do not switch an already-applied fresh state into
existing mode: that would propose removal of fresh-owned resources. Existing
mode requires a separate imported-state preview with zero replacements,
deletions, or private-route changes before any apply.

Fresh-owned VPC and private resources use `prevent_destroy`, so Terraform
rejects an unsafe switch from applied fresh state to `existing`. A reviewed
ownership migration is required instead.
