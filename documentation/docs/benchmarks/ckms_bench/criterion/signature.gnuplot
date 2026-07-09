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
set xtics ("ecdsa-p256/sign" 0, "ecdsa-p256/verify" 1, "ecdsa-p384/sign" 2, "ecdsa-p384/verify" 3, "ecdsa-p521/sign" 4, "ecdsa-p521/verify" 5, "ecdsa-secp256k1/sign" 6, "ecdsa-secp256k1/verify" 7, "eddsa-ed25519/sign" 8, "eddsa-ed25519/verify" 9, "eddsa-ed448/sign" 10, "eddsa-ed448/verify" 11, "ml-dsa/sign/44" 12, "ml-dsa/sign/65" 13, "ml-dsa/sign/87" 14, "ml-dsa/verify/44" 15, "ml-dsa/verify/65" 16, "ml-dsa/verify/87" 17, "rsa-pkcs1v15/sign" 18, "rsa-pkcs1v15/verify" 19, "rsa-pss/sign" 20, "rsa-pss/sign/4096" 21, "rsa-pss/verify" 22, "rsa-pss/verify/4096" 23, "slh-dsa/sign/SHA2-128f" 24, "slh-dsa/sign/SHA2-256f" 25, "slh-dsa/sign/SHAKE-128f" 26, "slh-dsa/verify/SHA2-128f" 27, "slh-dsa/verify/SHA2-256f" 28, "slh-dsa/verify/SHAKE-128f" 29)
plot 'signature.dat' using ($1+-0.267):2 with boxes lw 1 title 'ttlv-json', \
     'signature.dat' using ($1+0.000):3 with boxes lw 1 title 'ttlv-bytes', \
     'signature.dat' using ($1+0.267):4 with boxes lw 1 title 'jose'
