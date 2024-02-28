variable "prefix" {}

locals {
  ubuntu_ami_name = "${var.prefix}-cosmian-vm-kms-sev-ubuntu"
  redhat_ami_name = "${var.prefix}-cosmian-vm-kms-sev-redhat"
}

variable "project_id" {
  type    = string
  default = "cosmian-dev"
}

variable "ubuntu_source_image" {
  type    = string
  default = "alpha-20240227095902-cosmian-vm-sev-ubuntu"
}

variable "ubuntu_source_image_family" {
  type    = string
  default = ""
}

variable "redhat_source_image" {
  type    = string
  default = "release-1-0-1-cosmian-vm-sev-redhat-1707317295"
}

variable "redhat_source_image_family" {
  type    = string
  default = ""
}

variable "zone" {
  type    = string
  default = "europe-west4-a"
}

variable "ssh_username" {
  type    = string
  default = "root"
}

variable "ssh_timeout" {
  type    = string
  default = "10m"
}

variable "image_guest_os_features" {
  type    = list(string)
  default = ["SEV_SNP_CAPABLE"]
}

variable "network" {
  type    = string
  default = "default"
}

variable "subnetwork" {
  type    = string
  default = "default"
}

variable "tags" {
  type    = list(string)
  default = ["ssh-full"]
}

variable "use_os_login" {
  type    = bool
  default = true
}

variable "wait_to_add_ssh_keys" {
  type    = string
  default = "20s"
}

variable "image_licenses" {
  type    = string
  default = "projects/cosmian-public/global/licenses/cloud-marketplace-84a2e990cf18dca8-df1ebeb69c0ba664"
}

source "googlecompute" "ubuntu" {
  project_id             = var.project_id
  source_image           = var.ubuntu_source_image
  source_image_family    = var.ubuntu_source_image_family
  zone                   = var.zone
  ssh_username           = var.ssh_username
  ssh_timeout            = var.ssh_timeout
  image_name             = local.ubuntu_ami_name
  image_guest_os_features = var.image_guest_os_features
  network                = var.network
  subnetwork             = var.subnetwork
  tags                   = var.tags
  use_os_login           = var.use_os_login
  wait_to_add_ssh_keys   = var.wait_to_add_ssh_keys
  image_licenses         = var.image_licenses
}

// source "googlecompute" "redhat" {
//   project_id             = var.project_id
//   source_image           = var.redhat_source_image
//   source_image_family    = var.redhat_source_image_family
//   zone                   = var.zone
//   ssh_username           = var.ssh_username
//   ssh_timeout            = var.ssh_timeout
//   image_name             = local.redhat_ami_name
//   image_guest_os_features = var.image_guest_os_features
//   network                = var.network
//   subnetwork             = var.subnetwork
//   tags                   = var.tags
//   use_os_login           = var.use_os_login
//   wait_to_add_ssh_keys   = var.wait_to_add_ssh_keys
// }

build {
  sources = ["sources.googlecompute.ubuntu"]

  provisioner "file" {
    source      = "../scripts/install_kms_ubuntu.sh"
    destination = "/tmp/install_kms_ubuntu.sh"
  }

  provisioner "shell" {
    inline = [
      "chmod +x /tmp/install_kms_ubuntu.sh",
      "sudo /tmp/install_kms_ubuntu.sh"
    ]    
  }
}

// build {
//   sources = ["sources.googlecompute.redhat"]

//   provisioner "file" {
//     source      = "../scripts/install_kms_redhat.sh"
//     destination = "/tmp/install_kms_redhat.sh"
//   }

//   provisioner "shell" {
//     inline = [
//       "chmod +x /tmp/install_kms_redhat.sh",
//       "sudo /tmp/install_kms_redhat.sh"
//     ]       
//   }
// }