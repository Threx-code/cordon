output "bucket" {
  value = aws_s3_bucket.logs.id
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
}
