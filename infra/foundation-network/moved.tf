# Fresh-mode address upgrades. These moves are configuration-only and must be
# reviewed with a saved state preview before any existing state is upgraded.
moved {
  from = aws_vpc.this
  to   = aws_vpc.this[0]
}
moved {
  from = aws_subnet.hoodi
  to   = aws_subnet.hoodi[0]
}
moved {
  from = aws_route_table.system
  to   = aws_route_table.system[0]
}
moved {
  from = aws_route_table.hoodi
  to   = aws_route_table.hoodi[0]
}
moved {
  from = aws_route_table_association.hoodi
  to   = aws_route_table_association.hoodi[0]
}
moved {
  from = aws_default_security_group.foundation
  to   = aws_default_security_group.foundation[0]
}
moved {
  from = aws_kms_key.foundation_flow_logs
  to   = aws_kms_key.foundation_flow_logs[0]
}
moved {
  from = aws_cloudwatch_log_group.foundation_flow_logs
  to   = aws_cloudwatch_log_group.foundation_flow_logs[0]
}
moved {
  from = aws_iam_role.foundation_flow_logs
  to   = aws_iam_role.foundation_flow_logs[0]
}
moved {
  from = aws_iam_role_policy.foundation_flow_logs
  to   = aws_iam_role_policy.foundation_flow_logs[0]
}
moved {
  from = aws_flow_log.foundation
  to   = aws_flow_log.foundation[0]
}
