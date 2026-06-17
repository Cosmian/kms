set terminal svg size 2000,600 enhanced font 'Helvetica,12'
set output 'key_creation.svg'
set title 'Key Creation'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.267
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("EC/ES256" 0, "EC/ES384" 1, "RSA/2048" 2, "aes-128" 3, "aes-256" 4, "aes-gcm/oct/128" 5, "aes-gcm/oct/256" 6, "covercrypt/master-keypair" 7, "ec-p256" 8, "ec/ed25519" 9, "ec/ed448" 10, "ec/p256" 11, "ec/p384" 12, "ec/p521" 13, "ec/secp256k1" 14, "kem/ML-KEM-512" 15, "kem/ML-KEM-512/P-256" 16, "kem/ML-KEM-512/X25519" 17, "kem/ML-KEM-768" 18, "kem/ML-KEM-768/P-256" 19, "kem/ML-KEM-768/X25519" 20, "pqc/ML-DSA-44" 21, "pqc/ML-DSA-65" 22, "pqc/ML-DSA-87" 23, "pqc/ML-KEM-1024" 24, "pqc/ML-KEM-512" 25, "pqc/ML-KEM-768" 26, "pqc/SLH-DSA-SHA2-128f" 27, "pqc/SLH-DSA-SHA2-128s" 28, "pqc/SLH-DSA-SHA2-192f" 29, "pqc/SLH-DSA-SHA2-192s" 30, "pqc/SLH-DSA-SHA2-256f" 31, "pqc/SLH-DSA-SHA2-256s" 32, "pqc/SLH-DSA-SHAKE-128f" 33, "pqc/SLH-DSA-SHAKE-128s" 34, "pqc/SLH-DSA-SHAKE-192f" 35, "pqc/SLH-DSA-SHAKE-192s" 36, "pqc/SLH-DSA-SHAKE-256f" 37, "pqc/SLH-DSA-SHAKE-256s" 38, "pqc/X25519MLKEM768" 39, "pqc/X448MLKEM1024" 40, "rsa-2048" 41, "rsa/rsa-2048" 42, "rsa/rsa-3072" 43, "rsa/rsa-4096" 44, "symmetric/aes-128" 45, "symmetric/aes-192" 46, "symmetric/aes-256" 47, "symmetric/chacha20-256" 48)
plot 'key_creation.dat' using ($1+-0.267):2 with boxes lw 1 title 'ttlv-json', \
     'key_creation.dat' using ($1+0.000):3 with boxes lw 1 title 'ttlv-bytes', \
     'key_creation.dat' using ($1+0.267):4 with boxes lw 1 title 'jose'
