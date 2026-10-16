terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ==============================================================================
# CloudWatch Log Group with KMS Encryption and Pinned Retention
# ==============================================================================
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/ecs/${var.app_name}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.secrets_key.arn

  tags = {
    Name        = "${var.app_name}-logs"
    Environment = var.environment
  }
}

# ==============================================================================
# ECS Cluster
# ==============================================================================
resource "aws_ecs_cluster" "main" {
  name = "${var.app_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "${var.app_name}-cluster"
    Environment = var.environment
  }
}

# ==============================================================================
# ECS Task Definition
# Security Controls:
# - Strict CPU and Memory resource limits
# - Read-only root filesystem
# - Drops all Linux kernel capabilities
# - Runs as dedicated non-root user (10001:10001)
# - Secrets injected via Secrets Manager ARN (no hardcoded credentials)
# ==============================================================================
resource "aws_ecs_task_definition" "app" {
  family                   = var.app_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = var.app_name
      image     = var.container_image
      essential = true
      user      = "10001:10001"

      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]

      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
      }

      readonlyRootFilesystem = true

      mountPoints = [
        {
          sourceVolume  = "tmp-volume"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]

      # Secrets sourced strictly from AWS Secrets Manager
      secrets = [
        {
          name      = "SECRET_KEY"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:SECRET_KEY::"
        },
        {
          name      = "DB_PASSWORD"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:DB_PASSWORD::"
        }
      ]

      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "DATABASE_URL"
          value = "sqlite:////tmp/vulntracker.db"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "api"
        }
      }

      healthCheck = {
        command     = ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 15
      }
    }
  ])

  volume {
    name = "tmp-volume"
  }

  tags = {
    Name        = "${var.app_name}-task-def"
    Environment = var.environment
  }
}

# ==============================================================================
# ECS Fargate Service
# Deployed in private subnets with restricted security group ingress
# ==============================================================================
resource "aws_ecs_service" "app" {
  name            = "${var.app_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  tags = {
    Name        = "${var.app_name}-service"
    Environment = var.environment
  }
}
