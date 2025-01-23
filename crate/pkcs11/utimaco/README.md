# Utimaco HSM

# Installing the simulator

The simulator is a 32-bit ELF application on Linux.
When developping on 64-bit ARM system, such as a recent macbook, the easiest way to run the simulator,
is to install a Windows VM.
Make sure that the VM network is in bridge mode so that it gets an IP address from the same network as the host.

The Linux PKCS#11 library is a 64-bit ELF.

## Download and run the simulator

Download the simulator from the Utimaco website:
https://support.hsm.utimaco.com/documents/20182/1924884/SecurityServerEvaluation-6.0.0.0.tar

To run the simulator on Windows, open a terminal and run the following command:

```shell
cd u.trust_anchor_integration_eval_bundle-6.0.0.0\Software\Windows\Simulator\sim5_windows\bin
.\bl_sim5.exe -h -o -d ..\devices\
```

The simulator should launch on the IP address of the host machine and port 3001 and print the following message:

```
Utimaco CryptoServer Simulator HSD process started


25.01.22 22:50:49 SMOS SDK Ver. 5.7.0.0 (Nov 26 2024) started [0]
25.01.22 22:50:49 Compiler Ver. 19.0
25.01.22 22:50:49 CPU clock frequency: 24000000
25.01.22 22:50:49 Devices directory: '..\devices\'
25.01.22 22:50:51 Sensory Controller Ver. 2.0.0.42 [0/0]
25.01.22 22:50:51 Real Random Number Generator initialized with:
  RESEED_INTERVAL = 1000
  PREDICTION_RESISTANCE = 0
  REALRANDOM_SHARE = 3
25.01.22 22:50:51 Pseudo Random Number Generator initialized with:
  RESEED_INTERVAL = 1000
  PREDICTION_RESISTANCE = 0
  REALRANDOM_SHARE = 0
25.01.22 22:50:51 Load module 'adm.msc' from FLASHFILE
25.01.22 22:50:51 Load module 'cmds.msc' from FLASHFILE
25.01.22 22:50:51 CMDS: .pscf support enabled
25.01.22 22:50:51 Load module 'crypt.msc' from FLASHFILE
...
```

## Install the PKCS#11 library

Install a Linux VM in bridge mode and make sure it can access the simulator

```
telnet <simulator_ip> 3001
```

Download the simulator from the Utimaco website:
https://support.hsm.utimaco.com/documents/20182/1924884/SecurityServerEvaluation-6.0.0.0.tar

Create a configuration directory and copy a sample configuration file

```bash
mkdir -p /etc/utimaco
chmod 755 /etc/utimaco
cp u.trust_anchor_integration_eval_bundle-6.0.0.0/Software/Linux/Crypto_APIs/PKCS11_R3/sample/cs_pkcs11_R3.cfg /etc/utimaco/
```

Edit the configuration file to enable logging and set the simulator IP address and port:

```bash
sudo vim /etc/utimaco/cs_pkcs11_R3.cfg
```

```
...
Logpath = /tmp
...
Logging = 3
...
Device = 3001@<simulator_ip>
...
```
