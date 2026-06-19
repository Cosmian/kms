# Load Test Benchmarks

> Generated on 2026-06-02 08:56:23 UTC
>
> KMS server version: "5.23.0 (OpenSSL 3.6.2 7 Apr 2026-FIPS)"

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
CPU(s) scaling MHz:                      28%
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
| 1 | 1276.5 | 0.6 | 1.8 | 3.2 | 6384 |
| 2 | 2565.6 | 0.6 | 1.7 | 3.4 | 12830 |
| 4 | 1821.6 | 1.9 | 4.5 | 5.6 | 9115 |
| 8 | 6210.5 | 1.2 | 1.8 | 2.1 | 31064 |
| 16 | 8085.2 | 1.9 | 3.1 | 4.4 | 40446 |
| 32 | 12236.4 | 2.6 | 3.4 | 4.0 | 61207 |

### key-creation/aes-sym

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 1292.9 | 0.6 | 1.1 | 4.2 | 6465 |
| 2 | 2380.6 | 0.6 | 1.3 | 10.6 | 11906 |
| 4 | 1639.3 | 1.8 | 5.1 | 17.1 | 8215 |
| 8 | 3429.7 | 1.6 | 5.6 | 17.0 | 17155 |
| 16 | 6738.4 | 1.8 | 6.8 | 7.7 | 33708 |
| 32 | 6718.6 | 4.0 | 10.1 | 11.8 | 33619 |

### sign-verify/ecdsa-p256

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 1377.9 | 0.7 | 0.9 | 1.2 | 6890 |
| 2 | 2212.2 | 0.7 | 1.9 | 3.2 | 11062 |
| 4 | 2167.0 | 1.4 | 4.5 | 5.8 | 10837 |
| 8 | 5550.1 | 1.4 | 1.9 | 2.2 | 27760 |
| 16 | 6977.1 | 2.2 | 3.7 | 4.4 | 34898 |
| 32 | 11680.1 | 2.7 | 3.7 | 4.3 | 58433 |

### batch/aes-gcm-10

| Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Samples |
|-------------|-------------------|----------|----------|----------|---------|
| 1 | 875.3 | 1.1 | 1.4 | 3.6 | 4377 |
| 2 | 1562.6 | 1.2 | 2.1 | 3.1 | 7814 |
| 4 | 1981.4 | 1.8 | 3.7 | 5.2 | 9908 |
| 8 | 3310.2 | 2.4 | 3.2 | 3.4 | 16561 |
| 16 | 4728.1 | 3.3 | 4.8 | 5.8 | 23650 |
| 32 | 7111.9 | 4.4 | 5.8 | 6.5 | 35593 |
