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
set xtics ("EC/ES256" 0, "EC/ES384" 1, "RSA/2048" 2, "aes-gcm/oct/128" 3, "aes-gcm/oct/256" 4, "ec/ed25519" 5, "ec/ed448" 6, "ec/p256" 7, "ec/p384" 8, "ec/p521" 9, "ec/secp256k1" 10, "pqc/ML-DSA-44" 11, "pqc/ML-DSA-65" 12, "pqc/ML-DSA-87" 13, "pqc/ML-KEM-1024" 14, "pqc/ML-KEM-512" 15, "pqc/ML-KEM-768" 16, "rsa/rsa-4096" 17, "symmetric/aes-128" 18, "symmetric/aes-192" 19, "symmetric/aes-256" 20, "symmetric/chacha20-256" 21)
plot 'key_creation.dat' using ($1+-0.267):2 with boxes lw 1 title 'ttlv-json', \
     'key_creation.dat' using ($1+0.000):3 with boxes lw 1 title 'ttlv-bytes', \
     'key_creation.dat' using ($1+0.267):4 with boxes lw 1 title 'jose'
