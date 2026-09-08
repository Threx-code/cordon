# Restricted ingress and a non-privileged workload.
resource "aws_security_group_rule" "internal_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}

resource "aws_s3_bucket_public_access_block" "private" {
  block_public_acls   = true
  block_public_policy = true
}
