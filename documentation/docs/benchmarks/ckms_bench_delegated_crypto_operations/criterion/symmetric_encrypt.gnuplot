set terminal svg size 1200,600 enhanced font 'Helvetica,12'
set output 'symmetric_encrypt.svg'
set title 'Symmetric Encryption'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.800
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("hsm-aes-cbc/encrypt/256" 0, "hsm-aes-gcm/encrypt/256" 1)
plot 'symmetric_encrypt.dat' using ($1+0.000):2 with boxes lw 1 title 'ttlv-json'
