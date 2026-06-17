set terminal svg size 2000,600 enhanced font 'Helvetica,12'
set output 'signature.svg'
set title 'Sign / Verify'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.267
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("ecdsa-p256/sign" 0, "ecdsa-p256/verify" 1, "ecdsa-p384/sign" 2, "ecdsa-p384/verify" 3, "ecdsa-p521/sign" 4, "ecdsa-p521/verify" 5, "ecdsa-secp256k1/sign" 6, "ecdsa-secp256k1/verify" 7, "eddsa-ed25519/sign" 8, "eddsa-ed25519/verify" 9, "eddsa-ed448/sign" 10, "eddsa-ed448/verify" 11, "ml-dsa/sign/44" 12, "ml-dsa/sign/65" 13, "ml-dsa/sign/87" 14, "ml-dsa/verify/44" 15, "ml-dsa/verify/65" 16, "ml-dsa/verify/87" 17, "rsa-pss/sign/2048" 18, "rsa-pss/sign/3072" 19, "rsa-pss/sign/4096" 20, "rsa-pss/verify/2048" 21, "rsa-pss/verify/3072" 22, "rsa-pss/verify/4096" 23, "sign/ES256" 24, "sign/ES384" 25, "sign/EdDSA" 26, "sign/PS256" 27, "sign/RS256" 28, "slh-dsa/sign/SHA2-128f" 29, "slh-dsa/sign/SHA2-128s" 30, "slh-dsa/sign/SHA2-192f" 31, "slh-dsa/sign/SHA2-192s" 32, "slh-dsa/sign/SHA2-256f" 33, "slh-dsa/sign/SHA2-256s" 34, "slh-dsa/sign/SHAKE-128f" 35, "slh-dsa/sign/SHAKE-128s" 36, "slh-dsa/sign/SHAKE-192f" 37, "slh-dsa/sign/SHAKE-192s" 38, "slh-dsa/sign/SHAKE-256f" 39, "slh-dsa/sign/SHAKE-256s" 40, "slh-dsa/verify/SHA2-128f" 41, "slh-dsa/verify/SHA2-128s" 42, "slh-dsa/verify/SHA2-192f" 43, "slh-dsa/verify/SHA2-192s" 44, "slh-dsa/verify/SHA2-256f" 45, "slh-dsa/verify/SHA2-256s" 46, "slh-dsa/verify/SHAKE-128f" 47, "slh-dsa/verify/SHAKE-128s" 48, "slh-dsa/verify/SHAKE-192f" 49, "slh-dsa/verify/SHAKE-192s" 50, "slh-dsa/verify/SHAKE-256f" 51, "slh-dsa/verify/SHAKE-256s" 52, "verify/ES256" 53, "verify/ES384" 54, "verify/EdDSA" 55, "verify/PS256" 56, "verify/RS256" 57)
plot 'signature.dat' using ($1+-0.267):2 with boxes lw 1 title 'ttlv-json', \
     'signature.dat' using ($1+0.000):3 with boxes lw 1 title 'ttlv-bytes', \
     'signature.dat' using ($1+0.267):4 with boxes lw 1 title 'jose'
