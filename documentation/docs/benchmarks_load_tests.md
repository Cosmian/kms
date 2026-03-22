# Load Test Benchmarks

> Generated on 2026-03-25 05:42:33 UTC
>
> KMS server version: "5.17.0 (OpenSSL 3.6.0 1 Oct 2025-non-FIPS)"

## Machine Info

```
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
CPU(s) scaling MHz:                      19%
CPU max MHz:                             5500,0000
CPU min MHz:                             800,0000
BogoMIPS:                                2227,20
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb intel_pt sha_ni xsaveopt xsavec xgetbv1 xsaves split_lock_detect user_shstk avx_vnni dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp hwp_pkg_req hfi vnmi umip pku ospke waitpkg gfni vaes vpclmulqdq tme rdpid movdiri movdir64b fsrm md_clear serialize pconfig arch_lbr ibt flush_l1d arch_capabilities ibpb_exit_to_user
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
| 1 | 8112.6 | 0.1 | 0.2 | 0.3 | 40565 |
| 2 | 16638.4 | 0.1 | 0.2 | 0.4 | 83198 |
| 4 | 23325.1 | 0.1 | 0.3 | 0.5 | 116639 |
| 8 | 18453.2 | 0.4 | 0.6 | 0.8 | 92273 |
| 16 | 23122.3 | 0.7 | 0.8 | 0.9 | 115626 |
| 32 | 22841.4 | 1.4 | 1.5 | 1.6 | 114240 |

### key-creation/aes-sym

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 445.6 | 2.3 | 3.0 | 3.5 | 2229 |
| 2 | 507.4 | 4.0 | 5.1 | 5.8 | 2538 |
| 4 | 525.7 | 7.9 | 9.8 | 11.9 | 2631 |
| 8 | 338.6 | 16.1 | 70.5 | 75.5 | 1718 |
| 16 | 118.5 | 133.8 | 153.3 | 161.9 | 607 |
| 32 | 111.4 | 267.2 | 358.5 | 380.4 | 595 |

### sign-verify/ecdsa-p256

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 2164.7 | 0.4 | 0.5 | 0.7 | 10824 |
| 2 | 4119.8 | 0.5 | 0.7 | 0.9 | 20600 |
| 4 | 6717.0 | 0.5 | 1.0 | 1.4 | 33589 |
| 8 | 8003.1 | 1.0 | 1.3 | 1.4 | 40024 |
| 16 | 11093.7 | 1.4 | 2.3 | 2.8 | 55485 |
| 32 | 10876.9 | 2.9 | 3.8 | 4.0 | 54415 |

### batch/aes-gcm-10

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 3389.8 | 0.2 | 0.7 | 1.1 | 16950 |
| 2 | 6689.0 | 0.3 | 0.5 | 0.9 | 33447 |
| 4 | 6314.1 | 0.5 | 1.5 | 2.5 | 31574 |
| 8 | 10451.1 | 0.8 | 1.2 | 1.4 | 52262 |
| 16 | 15534.1 | 1.0 | 1.4 | 1.5 | 77685 |
| 32 | 18506.6 | 1.7 | 2.1 | 2.4 | 92562 |
