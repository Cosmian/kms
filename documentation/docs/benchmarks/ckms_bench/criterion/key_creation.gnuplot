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
set xtics ("EC/ES256" 0, "EC/ES384" 1, "RSA/2048" 2, "aes-gcm/oct/128" 3, "aes-gcm/oct/256" 4, "covercrypt/master-keypair" 5, "ec/ed25519" 6, "ec/ed448" 7, "ec/p256" 8, "ec/p384" 9, "ec/p521" 10, "ec/secp256k1" 11, "kem/ML-KEM-512" 12, "kem/ML-KEM-512/P-256" 13, "kem/ML-KEM-512/X25519" 14, "kem/ML-KEM-768" 15, "kem/ML-KEM-768/P-256" 16, "kem/ML-KEM-768/X25519" 17, "pqc/ML-DSA-44" 18, "pqc/ML-DSA-65" 19, "pqc/ML-DSA-87" 20, "pqc/ML-KEM-1024" 21, "pqc/ML-KEM-512" 22, "pqc/ML-KEM-768" 23, "pqc/X25519MLKEM768" 24, "pqc/X448MLKEM1024" 25, "rsa/rsa-4096" 26, "symmetric/aes-128" 27, "symmetric/aes-192" 28, "symmetric/aes-256" 29, "symmetric/chacha20-256" 30)
plot 'key_creation.dat' using ($1+-0.267):2 with boxes lw 1 title 'ttlv-json', \
     'key_creation.dat' using ($1+0.000):3 with boxes lw 1 title 'ttlv-bytes', \
     'key_creation.dat' using ($1+0.267):4 with boxes lw 1 title 'jose'
