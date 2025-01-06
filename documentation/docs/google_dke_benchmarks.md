
# Benchmarks on a virtual machine with 2 vCPUs

- [Benchmarks on a virtual machine with 2 vCPUs](#benchmarks-on-a-virtual-machine-with-2-vcpus)
    - [Benchmarks for Google CSE and Microsoft DKE](#benchmarks-for-google-cse-and-microsoft-dke)
        - [Notes](#notes)
    - [Concurrent Encryption/decryption requests per 1 core CPU](#concurrent-encryptiondecryption-requests-per-1-core-cpu)
        - [AES-256-GCM](#aes-256-gcm)
        - [RSA-4096 PKCSv1.5](#rsa-4096-pkcsv15)
        - [RSA-4096 OAEP](#rsa-4096-oaep)
    - [VM capacity](#vm-capacity)
        - [What does mean 2 vCPUs but 1 core CPU](#what-does-mean-2-vcpus-but-1-core-cpu)
            - [How This Works](#how-this-works)
            - [Why Use 2 vCPUs on 1 Core?](#why-use-2-vcpus-on-1-core)
        - [Machine Details](#machine-details)

## Benchmarks for Google CSE and Microsoft DKE

These benchmark results deal with the algorithms used in the **Google CSE** and **Microsoft DKE** contexts:

- `AES 256 GCM` is used for **Google Drive** and **Google Meet**,
- `RSA PKCSv1.5` is used for **GMail**.
- `RSA OAEP` is used for **Microsoft DKE**.

Users perform one single operation at a time: either 1 plaintext encryption or 1 ciphertext decryption. Benchmarks vary the number of simultaneous operations.

The benchmarks were run on the **smallest** GCP Virtual Machine with 2 vCPUs (but 1 core CPU) and 2GB of RAM.

### Notes

- No network latency was considered.
- On a 2 vCPUs machine, 1 vCPU is used by the OS constantly.

## Concurrent Encryption/decryption requests per 1 core CPU

### AES-256-GCM

|                     | `encrypt`   | `decrypt`   |
| :------------------ | :---------- | :---------- |
| **`1 request`**     | `440.57 us` | `445.04 us` |
| **`10 requests`**   | `598.59 us` | `563.24 us` |
| **`50 requests`**   | `847.94 us` | `795.68 us` |
| **`100 requests`**  | `1.17 ms`   | `1.04 ms`   |
| **`500 requests`**  | `3.56 ms`   | `2.92 ms`   |
| **`1000 requests`** | `6.50 ms`   | `5.28 ms`   |

**Note**: In a single request, the plaintext size is 64 bytes.

### RSA-4096 PKCSv1.5

|                     | `encrypt`   | `decrypt`   |
| :------------------ | :---------- | :---------- |
| **`1 request`**     | `673.26 us` | `5.93 ms`   |
| **`10 requests`**   | `4.85 ms`   | `57.14 ms`  |
| **`50 requests`**   | `21.57 ms`  | `284.79 ms` |
| **`100 requests`**  | `42.70 ms`  | `568.55 ms` |
| **`500 requests`**  | `210.01 ms` | `2.84 s`    |
| **`1000 requests`** | `423.91 ms` | `5.70 s`    |

**Note**:

- RSA PKCSv1.5 is still used in GMail.
- In a single request, the plaintext size is 32 bytes.

### RSA-4096 OAEP

|                     | `encrypt`   | `decrypt`   |
| :------------------ | :---------- | :---------- |
| **`1 request`**     | `682.76 us` | `5.95 ms`   |
| **`10 requests`**   | `4.68 ms`   | `57.11 ms`  |
| **`50 requests`**   | `21.69 ms`  | `284.39 ms` |
| **`100 requests`**  | `42.93 ms`  | `568.36 ms` |
| **`500 requests`**  | `211.73 ms` | `2.84 s`    |
| **`1000 requests`** | `434.21 ms` | `5.70 s`    |

**Note**:

- RSA OAEP is used in Microsoft DKE.
- In a single request, the plaintext size is 32 bytes.

## VM capacity

In brief, benchmarks are run on a GCP Virtual Machine with 2 vCPUs (1 core) and 2GB of RAM.

### What does mean 2 vCPUs but 1 core CPU

When you see specifications like "2 vCPUs but 1 core CPU," it's describing a setup where the virtual resources and physical resources are different.

Here's what it means:

- **Core CPU**: This means the physical CPU has only one core. Physically, there's one core capable of executing instructions.

- **vCPUs**: Virtual CPUs (vCPUs) represent virtualized CPU resources assigned to a virtual machine (VM). Here, 2 vCPUs mean that the hypervisor (virtualization layer) presents two virtual CPUs to the VM, so the operating system and applications on the VM see and can use two CPUs.

#### How This Works

In virtualization, a single physical CPU core can handle multiple vCPUs. This is done by time-slicing, where the hypervisor schedules different vCPUs to use the same physical core at different times, giving the appearance of multiple CPUs.

#### Why Use 2 vCPUs on 1 Core?

This setup is often used to provide a balance between performance and resource utilization in environments with limited CPU resources, like cloud or shared environments. While it's not as fast as having two physical cores, it can still improve performance for applications that can utilize multiple threads, albeit with shared processing time.

### Machine Details

```shell
$ lscpu

Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          48 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   2
  On-line CPU(s) list:    0,1
Vendor ID:                AuthenticAMD
  BIOS Vendor ID:         Google
  Model name:             AMD EPYC 7B13
    BIOS Model name:        CPU @ 2.0GHz
    BIOS CPU family:      1
    CPU family:           25
    Model:                1
    Thread(s) per core:   2
    Core(s) per socket:   1
    Socket(s):            1
    Stepping:             0
    BogoMIPS:             4899.99
    Flags:                fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_t
                          sc cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalign
                          sse 3dnowprefetch osvw topoext ssbd ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 clzero xsaveerptr
                           arat npt nrip_save umip vaes vpclmulqdq rdpid fsrm
Virtualization features:
  Hypervisor vendor:      KVM
  Virtualization type:    full
Caches (sum of all):
  L1d:                    32 KiB (1 instance)
  L1i:                    32 KiB (1 instance)
  L2:                     512 KiB (1 instance)
  L3:                     32 MiB (1 instance)
NUMA:
  NUMA node(s):           1
  NUMA node0 CPU(s):      0,1
Vulnerabilities:
  Gather data sampling:   Not affected
  Itlb multihit:          Not affected
  L1tf:                   Not affected
  Mds:                    Not affected
  Meltdown:               Not affected
  Mmio stale data:        Not affected
  Reg file data sampling: Not affected
  Retbleed:               Not affected
  Spec rstack overflow:   Vulnerable: Safe RET, no microcode
  Spec store bypass:      Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:             Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:             Mitigation; Retpolines; IBPB conditional; IBRS_FW; STIBP conditional; RSB filling; PBRSB-eIBRS Not affected; BHI Not affected
  Srbds:                  Not affected
  Tsx async abort:        Not affected
```
