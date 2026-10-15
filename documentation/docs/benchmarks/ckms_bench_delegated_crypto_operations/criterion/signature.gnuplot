set terminal svg size 1280,600 enhanced font 'Helvetica,12'
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
set xtics ("hsm-ecdsa-p256/sign" 0, "hsm-ecdsa-p384/sign" 1, "hsm-eddsa-ed25519/sign" 2, "hsm-eddsa-ed448/sign" 3, "hsm-rsa-pkcs1v15-sha1/sign/2048" 4, "hsm-rsa-pkcs1v15-sha256/sign/2048" 5, "hsm-rsa-pkcs1v15-sha384/sign/2048" 6, "hsm-rsa-pkcs1v15-sha512/sign/2048" 7, "hsm-rsa-pss/sign/2048" 8)
plot 'signature.dat' using ($1+0.000):2 with boxes lw 1 title 'ttlv-json'
