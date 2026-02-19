output "vpc_id" {
  description = "The ID of the created VPC"
  value       = aws_vpc.main_secure_vpc.id
}

output "web_server_public_ip" {
  description = "Public IP of the web server for auditing"
  value       = aws_instance.web_server.public_ip
}

output "private_subnet_id" {
  description = "The ID of the isolated DB subnet"
  value       = aws_subnet.private_db.id
}
