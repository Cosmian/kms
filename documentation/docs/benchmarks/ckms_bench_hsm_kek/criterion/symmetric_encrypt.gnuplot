set terminal svg size 2000,600 enhanced font 'Helvetica,12'
set output 'symmetric_encrypt.svg'
set title 'Symmetric Encryption'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.267
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("aes-gcm-siv/decrypt/128" 0, "aes-gcm-siv/decrypt/256" 1, "aes-gcm-siv/encrypt/128" 2, "aes-gcm-siv/encrypt/256" 3, "aes-gcm/decrypt/128" 4, "aes-gcm/decrypt/192" 5, "aes-gcm/decrypt/256" 6, "aes-gcm/encrypt/128" 7, "aes-gcm/encrypt/192" 8, "aes-gcm/encrypt/256" 9, "aes-xts/decrypt/128" 10, "aes-xts/decrypt/256" 11, "aes-xts/encrypt/128" 12, "aes-xts/encrypt/256" 13, "chacha20-poly1305/decrypt/256" 14, "chacha20-poly1305/encrypt/256" 15, "salsa-sealed-box/decrypt" 16, "salsa-sealed-box/encrypt" 17)
plot 'symmetric_encrypt.dat' using ($1+-0.267):2 with boxes lw 1 title 'ttlv-json', \
     'symmetric_encrypt.dat' using ($1+0.000):3 with boxes lw 1 title 'ttlv-bytes', \
     'symmetric_encrypt.dat' using ($1+0.267):4 with boxes lw 1 title 'jose'
