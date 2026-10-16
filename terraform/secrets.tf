# ==============================================================================
# KMS Customer Managed Key for Secrets Encryption
# ==============================================================================
resource "aws_kms_key" "secrets_key" {
  description             = "KMS key for encrypting VulnTracker application secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.app_name}-kms-key"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_kms_alias" "secrets_key_alias" {
  name          = "alias/${var.app_name}-secrets"
  target_key_id = aws_kms_key.secrets_key.key_id
}

# ==============================================================================
# AWS Secrets Manager Secret
# Zero hardcoded credentials in manifests - values injected securely via IAM
# ==============================================================================
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "${var.environment}/${var.app_name}/credentials"
  description             = "Production credentials for VulnTracker API (JWT secret, DB password)"
  kms_key_id              = aws_kms_key.secrets_key.arn
  recovery_window_in_days = 7

  tags = {
    Name        = "${var.app_name}-secrets"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Example version placeholder (actual values populated out-of-band via CLI or Vault)
resource "aws_secretsmanager_secret_version" "app_secrets_initial" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    SECRET_KEY  = "PLACEHOLDER_SET_VIA_SECRETS_MANAGER"
    DB_PASSWORD = "PLACEHOLDER_SET_VIA_SECRETS_MANAGER"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}
