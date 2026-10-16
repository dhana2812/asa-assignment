# ==============================================================================
# Application Load Balancer Security Group
# Restricts public ingress to HTTPS (port 443) only
# ==============================================================================
resource "aws_security_group" "alb" {
  name        = "${var.app_name}-alb-sg"
  description = "Security group for VulnTracker public ALB - restricted to HTTPS"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow inbound HTTPS traffic from trusted public clients"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "Allow outbound HTTP traffic strictly to ECS service tasks"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  tags = {
    Name        = "${var.app_name}-alb-sg"
    Environment = var.environment
  }
}

# ==============================================================================
# ECS Task Security Group
# Least-privilege ingress: Only accepts traffic from the ALB on container port
# Zero direct internet ingress allowed
# ==============================================================================
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.app_name}-ecs-tasks-sg"
  description = "Security group for ECS tasks - restricted to ALB ingress only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Allow inbound traffic exclusively from the ALB security group"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Allow outbound HTTPS for AWS API calls, ECR pulls, and webhook notifications"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.app_name}-ecs-tasks-sg"
    Environment = var.environment
  }
}
