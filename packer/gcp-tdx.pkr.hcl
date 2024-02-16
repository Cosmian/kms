/*
Copy the tdx capable image into the intel-enclaves project before building the image with packer.
To do so, run the command below :
gcloud alpha compute --project=intel-enclaves images create ubuntu-2204-tdx-v20231011 --family=ubuntu-2204-lts  --source-image=ubuntu-2204-tdx-v20231011  --source-image-project=tdx-guest-image
*/

variable "prefix" {}

locals {
  ubuntu_ami_name = "${var.prefix}-cosmian-vm-tdx-ubuntu-{{timestamp}}"
}

variable "project_id" {
  type    = string
  default = "intel-enclaves"
}

variable "ubuntu_source_image" {
  type    = string
  default = "ubuntu-2204-tdx-v20231011"
}

variable "ubuntu_source_image_family" {
  type    = string
  default = "ubuntu-2204-lts"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
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
  default = ["UEFI_COMPATIBLE","VIRTIO_SCSI_MULTIQUEUE","GVNIC","TDX_CAPABLE"]
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
}

build {
  sources = ["sources.googlecompute.ubuntu"]

  provisioner "file" {
    source      = "../resources/conf/ima-policy"
    destination = "/tmp/ima-policy"
  }

  provisioner "file" {
    source      = "../resources/conf/agent.toml"
    destination = "/tmp/agent.toml"
  }

  provisioner "file" {
    source      = "../resources/scripts/cosmian_fstool"
    destination = "/tmp/cosmian_fstool"
  }

  provisioner "file" {
    source      = "./target/release/cosmian_vm_agent"
    destination = "/tmp/"
  }

  provisioner "file" {
    source      = "./target/release/cosmian_certtool"
    destination = "/tmp/"
  }

  provisioner "ansible" {
    playbook_file = "../ansible/cosmian_vm_playbook.yml"
    local_port    = 22
    use_proxy     = false
  }
}