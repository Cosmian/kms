# Utimaco HSM

# Installing the simulator

The simulator is a 32-bit ELF application on Linux.
When developping on 64-bit ARM system, such as a recent macbook, the easiest way to run the simulator,
is to install a Windows VM.
Make sure that the VM network is in bridge mode so that it gets an IP address from the same network as the host.
If bridging is not possible, start the VMs in NAT mode and
check [this paragraph](#when-a-bridged-network-is-not-possible)

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

## Configure the PKCS#11 connection

Install a Linux VM in bridge mode and make sure it can access the simulator

```
telnet <simulator_ip> 3001
```

Download the simulator from the Utimaco website:
https://support.hsm.utimaco.com/documents/20182/1924884/SecurityServerEvaluation-6.0.0.0.tar

Create a configuration directory and copy a sample configuration file

```bash
sudo mkdir -p /etc/utimaco
sudo chmod 755 /etc/utimaco
sudo cp u.trust_anchor_integration_eval_bundle-6.0.0.0/Software/Linux/Crypto_APIs/PKCS11_R3/sample/cs_pkcs11_R3.cfg /etc/utimaco/
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

Then make the PKCS#11 configuration file available to the library and tools:

```bash
export CS_PKCS11_R3_CFG=/etc/utimaco/cs_pkcs11_R3.cfg
```

## Test the PKCS#11 configuration

```bash
cd u.trust_anchor_integration_eval_bundle-6.0.0.0/Software/Linux/Administration
./p11tool2 Slot=0 GetSlotInfo
```

The output should be similar to:

```
CK_SLOT_INFO (slot ID: 0x00000000):

  slotDescription          33303031 40313932  2e313638 2e36382e |3001@192.168.68.|
                           3633202d 20534c4f  545f3030 30302020 |63 - SLOT_0000  |
                           20202020 20202020  20202020 20202020 |                |
                           20202020 20202020  20202020 20202020 |                |

  manufacturerID           5574696d 61636f20  49532047 6d624820 |Utimaco IS GmbH |
                           20202020 20202020  20202020 20202020 |                |

  flags: 0x00000005
    CKF_TOKEN_PRESENT    : CK_TRUE
    CKF_REMOVABLE_DEVICE : CK_FALSE
    CKF_HW_SLOT          : CK_TRUE

  hardwareVersion        : 5.02
  firmwareVersion        : 6.00
 ```

## When a bridged network is not possible

Say we have 2 VMs (one Linux with the PKCS#11 library, one Windows with the simulator)
running on a macos host. The simulator is listening on port 3001 on the Windows VM.

```
Linux VM       <---->      macos host       <---->    Windows VM  
                         192.168.177.25 
192.168.65.3             192.168.65.1              
                         192.168.161.1               192.168.161.138
```

Use an ssh tunnel to forward the port 3001 of the Windows VM to the 3001 of the Linux VM,
via the macOS host.

On the Linux VM, run

```sh
ssh -L 3001:192.168.161.138:3001 <macos_user>@192.168.65.1 -N -f
```

(the `-N` `-f` switches run the port forwarding in the background without opening a shell)

Update the PKCS#11 configuration file to point to localhost:

```sh
sudo vim /etc/utimaco/cs_pkcs11_R3.cfg
```

Set the Device to `3001@localhost`

Then check that the simulator is now accessible on port 3001 at localhost:

```sh
./p11tool2 Slot=0 GetSlotInfo
```

