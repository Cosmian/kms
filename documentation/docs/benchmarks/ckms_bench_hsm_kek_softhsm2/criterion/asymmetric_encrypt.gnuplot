set terminal svg size 2000,600 enhanced font 'Helvetica,12'
set output 'asymmetric_encrypt.svg'
set title 'Asymmetric Encryption'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.400
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("ecies/decrypt/P-256" 0, "ecies/decrypt/P-384" 1, "ecies/decrypt/P-521" 2, "ecies/encrypt/P-256" 3, "ecies/encrypt/P-384" 4, "ecies/encrypt/P-521" 5, "rsa-aes-kwp/decrypt/4096" 6, "rsa-aes-kwp/encrypt/4096" 7, "rsa-oaep/decrypt/4096" 8, "rsa-oaep/encrypt/4096" 9, "rsa-pkcs1v15/decrypt/4096" 10, "rsa-pkcs1v15/encrypt/4096" 11)
plot 'asymmetric_encrypt.dat' using ($1+-0.200):2 with boxes lw 1 title 'ttlv-json', \
     'asymmetric_encrypt.dat' using ($1+0.200):3 with boxes lw 1 title 'ttlv-bytes'
