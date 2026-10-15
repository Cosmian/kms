set terminal svg size 1640,600 enhanced font 'Helvetica,12'
set output 'signature.svg'
set title 'Sign / Verify'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.800
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("ecdsa-p256/sign" 0, "ecdsa-p256/verify" 1, "ecdsa-p384/sign" 2, "ecdsa-p384/verify" 3, "ecdsa-secp256k1/sign" 4, "ecdsa-secp256k1/verify" 5, "eddsa-ed25519/sign" 6, "eddsa-ed25519/verify" 7, "rsa-pkcs-sha256/sign" 8, "rsa-pkcs-sha256/verify" 9, "rsa-pss-sha256/sign" 10, "rsa-pss-sha256/verify" 11)
plot 'signature.dat' using ($1+0.000):2 with boxes lw 1 title 'pkcs11'
