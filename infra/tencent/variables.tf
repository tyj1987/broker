# infra/tencent/variables.tf

variable "region" {
  type        = string
  description = "Tencent region"
  default     = "ap-shanghai"
}

variable "image_tag" {
  type        = string
  description = "Docker image tag to deploy"
  default     = "latest"
}
