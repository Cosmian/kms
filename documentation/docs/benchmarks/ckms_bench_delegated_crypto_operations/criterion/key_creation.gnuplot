set terminal svg size 1200,600 enhanced font 'Helvetica,12'
set output 'key_creation.svg'
set title 'Key Creation'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.800
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("hsm-aes-256/create" 0, "hsm-ec-p256/create" 1, "hsm-ed25519/create" 2, "hsm-ed448/create" 3, "hsm-rsa-2048/create" 4)
plot 'key_creation.dat' using ($1+0.000):2 with boxes lw 1 title 'ttlv-json'
