# Load Test Benchmarks

> Generated on 2026-03-26 13:45:24 UTC
>
> KMS server version: "5.17.0 (OpenSSL 3.6.0 1 Oct 2025-non-FIPS)"

## Machine Info

```text
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           46 bits physical, 48 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  32
On-line CPU(s) list:                     0-31
Vendor ID:                               GenuineIntel
Model name:                              Intel(R) Core(TM) i9-14900T
CPU family:                              6
Model:                                   183
Thread(s) per core:                      2
Core(s) per socket:                      24
Socket(s):                               1
Stepping:                                1
CPU(s) scaling MHz:                      24%
CPU max MHz:                             5500,0000
CPU min MHz:                             800,0000
BogoMIPS:                                2227,20
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb intel_pt sha_ni xsaveopt xsavec xgetbv1 xsaves split_lock_detect user_shstk avx_vnni dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp hwp_pkg_req hfi vnmi umip pku ospke waitpkg gfni vaes vpclmulqdq time rdpid movdiri movdir64b fsrm md_clear serialize pconfig arch_lbr ibt flush_l1d arch_capabilities ibpb_exit_to_user
Virtualization:                          VT-x
L1d cache:                               896 KiB (24 instances)
L1i cache:                               1,3 MiB (24 instances)
L2 cache:                                32 MiB (12 instances)
L3 cache:                                36 MiB (1 instance)
NUMA node(s):                            1
NUMA node0 CPU(s):                       0-31
Vulnerability Gather data sampling:      Not affected
Vulnerability Indirect target selection: Not affected
Vulnerability Itlb multihit:             Not affected
Vulnerability L1tf:                      Not affected
Vulnerability Mds:                       Not affected
Vulnerability Meltdown:                  Not affected
Vulnerability Mmio stale data:           Not affected
Vulnerability Reg file data sampling:    Mitigation; Clear Register File
Vulnerability Retbleed:                  Not affected
Vulnerability Spec rstack overflow:      Not affected
Vulnerability Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
Vulnerability Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:                Mitigation; Enhanced / Automatic IBRS; IBPB conditional; PBRSB-eIBRS SW sequence; BHI BHI_DIS_S
Vulnerability Srbds:                     Not affected
Vulnerability Tsa:                       Not affected
Vulnerability Tsx async abort:           Not affected
Vulnerability Vmscape:                   Mitigation; IBPB before exit to userspace
```

## Results

### encrypt/aes-gcm

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 8094.6 | 0.1 | 0.2 | 0.4 | 40477 |
| 2 | 12022.6 | 0.1 | 0.4 | 0.6 | 60120 |
| 4 | 21172.9 | 0.1 | 0.4 | 0.6 | 105873 |
| 8 | 21359.6 | 0.4 | 0.6 | 0.7 | 106812 |
| 16 | 24830.1 | 0.6 | 0.9 | 1.0 | 124167 |
| 32 | 22704.5 | 1.4 | 1.5 | 1.6 | 113546 |

### key-creation/aes-sym

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 407.1 | 2.5 | 3.7 | 4.5 | 2036 |
| 2 | 513.6 | 4.0 | 4.9 | 5.8 | 2569 |
| 4 | 548.5 | 7.2 | 9.7 | 11.4 | 2746 |
| 8 | 388.3 | 15.7 | 66.7 | 74.4 | 1968 |
| 16 | 112.0 | 140.5 | 164.3 | 179.6 | 577 |
| 32 | 93.1 | 342.4 | 388.5 | 411.7 | 497 |

### sign-verify/ecdsa-p256

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 2050.7 | 0.4 | 0.7 | 1.0 | 10254 |
| 2 | 4089.4 | 0.5 | 0.7 | 1.0 | 20449 |
| 4 | 6378.3 | 0.6 | 1.0 | 1.3 | 31894 |
| 8 | 7368.6 | 1.1 | 1.4 | 1.6 | 36852 |
| 16 | 10165.6 | 1.5 | 2.6 | 3.2 | 50847 |
| 32 | 11606.3 | 2.8 | 3.7 | 4.0 | 58069 |

### batch/aes-gcm-10

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 3193.3 | 0.2 | 0.8 | 1.2 | 15968 |
| 2 | 6531.2 | 0.3 | 0.5 | 0.8 | 32658 |
| 4 | 5737.5 | 0.5 | 1.8 | 2.7 | 28692 |
| 8 | 10694.3 | 0.7 | 1.1 | 1.3 | 53478 |
| 16 | 15328.4 | 1.0 | 1.5 | 1.9 | 76658 |
| 32 | 18392.3 | 1.7 | 2.1 | 2.5 | 91991 |
