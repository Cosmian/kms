set terminal svg size 2000,600 enhanced font 'Helvetica,12'
set output 'asymmetric_encrypt.svg'
set title 'Asymmetric Encryption'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.267
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("covercrypt/decrypt" 0, "covercrypt/encrypt" 1, "ecies/decrypt/P-256" 2, "ecies/decrypt/P-384" 3, "ecies/decrypt/P-521" 4, "ecies/encrypt/P-256" 5, "ecies/encrypt/P-384" 6, "ecies/encrypt/P-521" 7, "rsa-aes-kwp/decrypt/4096" 8, "rsa-aes-kwp/encrypt/4096" 9, "rsa-oaep/decrypt/2048" 10, "rsa-oaep/decrypt/4096" 11, "rsa-oaep/encrypt/2048" 12, "rsa-oaep/encrypt/4096" 13, "rsa-pkcs1v15/decrypt/4096" 14, "rsa-pkcs1v15/encrypt/4096" 15)
plot 'asymmetric_encrypt.dat' using ($1+-0.267):2 with boxes lw 1 title 'ttlv-json', \
     'asymmetric_encrypt.dat' using ($1+0.000):3 with boxes lw 1 title 'ttlv-bytes', \
     'asymmetric_encrypt.dat' using ($1+0.267):4 with boxes lw 1 title 'jose'
