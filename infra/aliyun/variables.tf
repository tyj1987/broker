# infra/aliyun/variables.tf

variable "region" {
  type        = string
  description = "Aliyun region"
  default     = "cn-hangzhou"
}

variable "image_tag" {
  type        = string
  description = "Docker image tag to deploy"
  default     = "latest"
}
