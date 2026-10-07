terraform {
  required_version = ">= 1.6.0"

  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.2.0, < 4.0.0"
    }
    time = {
      source                = "hashicorp/time"
      version               = "0.12.1"
      configuration_aliases = [time.secondary]
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.3"
    }
  }
}
