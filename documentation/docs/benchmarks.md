
# Benchmarks on a 32 core CPU

- [Benchmarks on a 32 core CPU](#benchmarks-on-a-32-core-cpu)
  - [Notes](#notes)
  - [Concurrent Encryption/decryption requests per 32 core CPU](#concurrent-encryptiondecryption-requests-per-32-core-cpu)
    - [AES GCM - plaintext of 64 bytes](#aes-gcm---plaintext-of-64-bytes)
    - [RSA AES KEY WRAP - plaintext of 32 bytes](#rsa-aes-key-wrap---plaintext-of-32-bytes)
    - [RSA PKCSv1.5 - plaintext of 32 bytes](#rsa-pkcsv15---plaintext-of-32-bytes)
    - [RSA OAEP - plaintext of 32 bytes](#rsa-oaep---plaintext-of-32-bytes)
  - [VM capacity](#vm-capacity)
    - [Machine Details](#machine-details)

## Notes

- No network latency was considered.

## Concurrent Encryption/decryption requests per 32 core CPU

### AES GCM - plaintext of 64 bytes

|                     | `128-bit key encrypt` | `128-bit key decrypt` | `256-bit key encrypt` | `256-bit key decrypt` |
| :------------------ | :-------------------- | :-------------------- | :-------------------- | :-------------------- |
| **`1 request`**     | `83.23 us`            | `64.98 us`            | `66.73 us`            | `73.49 us`            |
| **`10 requests`**   | `102.45 us`           | `76.50 us`            | `122.34 us`           | `89.07 us`            |
| **`50 requests`**   | `247.15 us`           | `195.03 us`           | `275.85 us`           | `195.99 us`           |
| **`100 requests`**  | `382.18 us`           | `304.93 us`           | `397.01 us`           | `314.69 us`           |
| **`500 requests`**  | `1.57 ms`             | `1.40 ms`             | `1.59 ms`             | `1.36 ms`             |
| **`1000 requests`** | `3.02 ms`             | `2.52 ms`             | `2.97 ms`             | `2.57 ms`             |

### RSA AES KEY WRAP - plaintext of 32 bytes

|                     | `2048-bit key encrypt` | `2048-bit key decrypt` | `4096-bit key encrypt` | `4096-bit key decrypt` |
| :------------------ | :--------------------- | :--------------------- | :--------------------- | :--------------------- |
| **`1 request`**     | `135.88 us`            | `694.76 us`            | `171.04 us`            | `3.46 ms`              |
| **`10 requests`**   | `827.56 us`            | `6.31 ms`              | `1.27 ms`              | `32.55 ms`             |
| **`50 requests`**   | `3.89 ms`              | `32.31 ms`             | `6.02 ms`              | `165.09 ms`            |
| **`100 requests`**  | `7.47 ms`              | `63.17 ms`             | `11.89 ms`             | `328.98 ms`            |
| **`500 requests`**  | `36.39 ms`             | `315.27 ms`            | `57.21 ms`             | `1.69 s`               |
| **`1000 requests`** | `73.79 ms`             | `625.05 ms`            | `124.43 ms`            | `3.56 s`               |

### RSA PKCSv1.5 - plaintext of 32 bytes

|                     | `2048-bit key encrypt` | `2048-bit key decrypt` | `4096-bit key encrypt` | `4096-bit key decrypt` |
| :------------------ | :--------------------- | :--------------------- | :--------------------- | :--------------------- |
| **`1 request`**     | `112.18 us`            | `707.66 us`            | `194.84 us`            | `3.64 ms`              |
| **`10 requests`**   | `725.44 us`            | `6.29 ms`              | `1.18 ms`              | `33.79 ms`             |
| **`50 requests`**   | `3.49 ms`              | `32.22 ms`             | `5.88 ms`              | `173.29 ms`            |
| **`100 requests`**  | `6.50 ms`              | `61.20 ms`             | `10.96 ms`             | `355.21 ms`            |
| **`500 requests`**  | `33.35 ms`             | `312.68 ms`            | `54.41 ms`             | `1.75 s`               |
| **`1000 requests`** | `68.57 ms`             | `616.46 ms`            | `109.11 ms`            | `3.40 s`               |

### RSA OAEP - plaintext of 32 bytes

|                     | `2048-bit key encrypt` | `2048-bit key decrypt` | `4096-bit key encrypt` | `4096-bit key decrypt` |
| :------------------ | :--------------------- | :--------------------- | :--------------------- | :--------------------- |
| **`1 request`**     | `107.01 us`            | `683.28 us`            | `152.96 us`            | `3.43 ms`              |
| **`10 requests`**   | `800.19 us`            | `6.54 ms`              | `1.25 ms`              | `33.80 ms`             |
| **`50 requests`**   | `3.41 ms`              | `30.72 ms`             | `5.70 ms`              | `166.50 ms`            |
| **`100 requests`**  | `6.64 ms`              | `67.95 ms`             | `11.22 ms`             | `365.94 ms`            |
| **`500 requests`**  | `32.51 ms`             | `307.53 ms`            | `53.60 ms`             | `1.67 s`               |
| **`1000 requests`** | `65.34 ms`             | `605.93 ms`            | `101.62 ms`            | `3.24 s`               |

## VM capacity

Benchmarks are run on a physical machine with 32 CPUs and 32GB of RAM.

### Machine Details

```shell
$ lscpu

Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          46 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   32
  On-line CPU(s) list:    0-31
Vendor ID:                GenuineIntel
  Model name:             Intel(R) Core(TM) i9-14900T
    CPU family:           6
    Model:                183
    Thread(s) per core:   2
    Core(s) per socket:   24
    Socket(s):            1
    Stepping:             1
    CPU max MHz:          5500,0000
    CPU min MHz:          800,0000
    BogoMIPS:             2227.20
    Flags:                fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rd
                          rand lahf_lm abm 3dnowprefetch cpuid_fault epb ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb intel_pt sha_ni xsaveopt xsavec xgetbv1 xsaves split_lock_detect user_shstk avx_vnni dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp hwp_pkg_req hfi vnmi umip pku ospke waitpkg gfni vaes vpclmulqd
                          q tme rdpid movdiri movdir64b fsrm md_clear serialize pconfig arch_lbr ibt flush_l1d arch_capabilities
Virtualization features:  
  Virtualization:         VT-x
Caches (sum of all):      
  L1d:                    896 KiB (24 instances)
  L1i:                    1,3 MiB (24 instances)
  L2:                     32 MiB (12 instances)
  L3:                     36 MiB (1 instance)
NUMA:                     
  NUMA node(s):           1
  NUMA node0 CPU(s):      0-31
Vulnerabilities:          
  Gather data sampling:   Not affected
  Itlb multihit:          Not affected
  L1tf:                   Not affected
  Mds:                    Not affected
  Meltdown:               Not affected
  Mmio stale data:        Not affected
  Reg file data sampling: Mitigation; Clear Register File
  Retbleed:               Not affected
  Spec rstack overflow:   Not affected
  Spec store bypass:      Mitigation; Speculative Store Bypass disabled via prctl
  Spectre v1:             Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:             Mitigation; Enhanced / Automatic IBRS; IBPB conditional; RSB filling; PBRSB-eIBRS SW sequence; BHI BHI_DIS_S
  Srbds:                  Not affected
  Tsx async abort:        Not affected
```
