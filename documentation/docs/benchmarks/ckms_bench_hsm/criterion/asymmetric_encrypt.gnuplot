set terminal svg size 1200,600 enhanced font 'Helvetica,12'
set output 'asymmetric_encrypt.svg'
set title 'Asymmetric Encryption'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.800
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("hsm-rsa-oaep-sha1/encrypt/2048" 0, "hsm-rsa-oaep/encrypt/2048" 1, "hsm-rsa-pkcs1v15/encrypt/2048" 2)
plot 'asymmetric_encrypt.dat' using ($1+0.000):2 with boxes lw 1 title 'ttlv-json'
