set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'decrypt_rsa-pkcs.svg'
set title 'Throughput — decrypt/rsa-pkcs'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'decrypt_rsa-pkcs-5.27.1-pkcs11.dat' using 1:2 with linespoints lw 2 pt 7 title 'pkcs11'
