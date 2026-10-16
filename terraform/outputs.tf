output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.app.name
}

output "secrets_manager_secret_arn" {
  description = "ARN of the Secrets Manager secret storing application credentials"
  value       = aws_secretsmanager_secret.app_secrets.arn
}

output "ecs_task_security_group_id" {
  description = "Security group ID assigned to ECS tasks"
  value       = aws_security_group.ecs_tasks.id
}
