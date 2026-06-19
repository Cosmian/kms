# Load Test Benchmarks

> Generated on 2026-06-12 07:40:27 UTC
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
CPU(s) scaling MHz:                      33%
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

### encrypt/aes-gcm

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 1283.0 | 0.7 | 1.0 | 1.4 | 6416 |
| 2 | 2223.2 | 0.8 | 1.4 | 1.6 | 11117 |
| 4 | 2898.8 | 1.4 | 2.0 | 2.3 | 14498 |
| 8 | 3893.0 | 2.0 | 3.1 | 3.5 | 19474 |
| 16 | 4381.0 | 3.3 | 5.6 | 5.9 | 21920 |
| 32 | 4935.9 | 5.8 | 10.0 | 10.6 | 24703 |

### key-creation/aes-sym

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 236.1 | 4.1 | 4.8 | 7.4 | 1181 |
| 2 | 290.9 | 6.7 | 7.5 | 11.8 | 1456 |
| 4 | 349.2 | 10.3 | 19.7 | 22.0 | 1750 |
| 8 | 377.3 | 20.6 | 25.7 | 30.7 | 1895 |
| 16 | 356.2 | 44.6 | 55.8 | 60.7 | 1795 |
| 32 | 384.0 | 82.2 | 94.7 | 101.2 | 1950 |

### sign-verify/ecdsa-p256

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 323.6 | 3.1 | 3.4 | 3.5 | 1619 |
| 2 | 566.7 | 3.3 | 4.8 | 6.6 | 2834 |
| 4 | 964.5 | 3.9 | 6.8 | 7.4 | 4825 |
| 8 | 1278.3 | 5.8 | 8.5 | 9.1 | 6399 |
| 16 | 1847.7 | 9.7 | 11.6 | 12.5 | 9257 |
| 32 | 2229.7 | 14.1 | 19.6 | 22.8 | 11181 |

### batch/aes-gcm-10

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 649.9 | 1.5 | 1.7 | 2.2 | 3250 |
| 2 | 1224.0 | 1.5 | 2.1 | 2.6 | 6121 |
| 4 | 1966.8 | 1.9 | 2.9 | 3.4 | 9837 |
| 8 | 2409.0 | 3.3 | 4.5 | 5.0 | 12049 |
| 16 | 3066.6 | 5.0 | 7.4 | 7.8 | 15343 |
| 32 | 3545.9 | 8.5 | 13.0 | 13.9 | 17760 |
