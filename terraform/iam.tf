# ==============================================================================
# ECS Task Execution Role (used by ECS agent to pull images and fetch secrets)
# ==============================================================================
resource "aws_iam_role" "ecs_execution_role" {
  name = "${var.app_name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
      }
    ]
  })

  tags = {
    Name        = "${var.app_name}-execution-role"
    Environment = var.environment
  }
}

# AWS Managed policy for basic ECS execution (logs and ECR pull)
resource "aws_iam_role_policy_attachment" "ecs_execution_standard" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Least-privilege policy: Grant access strictly to VulnTracker secret and KMS key
resource "aws_iam_policy" "ecs_secrets_access" {
  name        = "${var.app_name}-secrets-policy"
  description = "Allows ECS execution role to retrieve VulnTracker secrets and decrypt with KMS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSpecificSecret"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [aws_secretsmanager_secret.app_secrets.arn]
      },
      {
        Sid    = "DecryptKmsKey"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = [aws_kms_key.secrets_key.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_secrets" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = aws_iam_policy.ecs_secrets_access.arn
}

# ==============================================================================
# ECS Task Role (used by the running application container)
# Minimal permissions - zero access to AWS infrastructure
# ==============================================================================
resource "aws_iam_role" "ecs_task_role" {
  name = "${var.app_name}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
      }
    ]
  })

  tags = {
    Name        = "${var.app_name}-task-role"
    Environment = var.environment
  }
}
