#!/bin/bash
set -ex

# sudo dpkg --add-architecture i386
# sudo apt-get update && sudo apt-get install libc6:i386 libstdc++6:i386

wget "https://package.cosmian.com/ci/hsm-simulator.tar.xz"
echo -n Extracting compressed archive...
tar -xvf hsm-simulator.tar.xz
rm hsm-simulator.tar.xz
./hsm-simulator/sim5_linux/bin/bl_sim5 -h -o -d ./hsm-simulator/sim5_linux/devices &

#sudo telnet localhost 3001
sudo cp ./hsm-simulator/libcs_pkcs11_R3.so /lib
sudo mkdir -p /etc/utimaco
sudo chmod 755 /etc/utimaco/
sudo cp ./hsm-simulator/cs_pkcs11_R3.cfg /etc/utimaco/
sudo chmod 766 /etc/utimaco/cs_pkcs11_R3.cfg
sudo echo -e "Logpath = /tmp\nLogging = 3\nDevice = 3001@localhost\n" > /etc/utimaco/cs_pkcs11_R3.cfg
export CS_PKCS11_R3_CFG=/etc/utimaco/cs_pkcs11_R3.cfg

cd ./hsm-simulator/Administration

# set the SO PIN to 11223344
./p11tool2 Slot=0 login=ADMIN,./key/ADMIN_SIM.key  InitToken=11223344
# Change the SO PIN to 12345678
./p11tool2 Slot=0 LoginSO=11223344 SetPin=11223344,12345678
# Set the User PIN to 11223344
./p11tool2 Slot=0 LoginSO=12345678 InitPin=11223344
# Change the User PIN to 12345678
./p11tool2 Slot=0 LoginUser=11223344 SetPin=11223344,12345678

./p11tool2 Slot=0 GetSlotInfo

cargo test -p utimaco_pkcs11_loader --features utimaco
