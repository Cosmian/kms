set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'decrypt_rsa-oaep-cached.svg'
set title 'Throughput — decrypt/rsa-oaep-cached'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'decrypt_rsa-oaep-cached-5.29.0-jose.dat' using 1:2 with linespoints lw 2 pt 7 title 'jose'
