This ansible is designed to work with packer.

You can run it anyway without packer as follow:

```console
# Be sure to first login using SSH through the AWS Console
# And then create the `cosmian` user
sudo useradd -s /bin/bash -d /home/cosmian -m -G sudo cosmian
sudo echo "cosmian ALL =(ALL) NOPASSWD:ALL" >> /etc/sudoers
# And then add your own `.ssh/id_rsa.pub` in the remote `.ssh/authorized_keys`
sudo su cosmian && cd
mkdir -p .ssh/
vi .ssh/authorized_keys


# Then on your localhost
export USERNAME=cosmian
export HOST=35.204.83.49
# From the root of the github repository
# Compile cosmian vm first using `cargo build`
scp target/debug/{cosmian_vm_agent,cosmian_certtool} $USERNAME@$HOST:/tmp
scp resources/conf/{ima-policy,agent.toml,ima-policy-selinux,agent_no_tpm.toml,instance_configs.cfg} $USERNAME@$HOST:/tmp
scp resources/scripts/cosmian_fstool $USERNAME@$HOST:/tmp
# Be sure to install deps: `pip install ansible ansible-core` and `ansible-galaxy collection install ansible.core` on your localhost
cd ansible
ansible-playbook cosmian_vm_playbook.yml -i ${HOST}, -u $USERNAME
```

The machine has been configured
