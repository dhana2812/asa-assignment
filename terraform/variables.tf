variable "aws_region" {
  description = "AWS region for VulnTracker deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "production"
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "vulntracker-api"
}

variable "container_image" {
  description = "Full container image reference with pinned tag or digest"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/vulntracker-api:v1.0.0"
}

variable "container_port" {
  description = "Port exposed by the VulnTracker FastAPI application"
  type        = number
  default     = 8000
}

variable "cpu" {
  description = "Fargate task CPU limit (units: 256 = 0.25 vCPU)"
  type        = number
  default     = 256
}

variable "memory" {
  description = "Fargate task Memory limit (MiB)"
  type        = number
  default     = 512
}

variable "vpc_id" {
  description = "VPC ID where the service and load balancer are deployed"
  type        = string
  default     = "vpc-0123456789abcdef0"
}

variable "private_subnet_ids" {
  description = "Private subnets for ECS tasks (restricted egress, no direct public IPs)"
  type        = list(string)
  default     = ["subnet-0123456789abcdef1", "subnet-0123456789abcdef2"]
}

variable "public_subnet_ids" {
  description = "Public subnets for Application Load Balancer"
  type        = list(string)
  default     = ["subnet-0123456789abcdef3", "subnet-0123456789abcdef4"]
}
