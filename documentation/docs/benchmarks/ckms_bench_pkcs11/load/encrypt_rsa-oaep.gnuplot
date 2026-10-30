set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'encrypt_rsa-oaep.svg'
set title 'Throughput — encrypt/rsa-oaep'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'encrypt_rsa-oaep-5.28.0-pkcs11.dat' using 1:2 with linespoints lw 2 pt 7 title 'pkcs11'
