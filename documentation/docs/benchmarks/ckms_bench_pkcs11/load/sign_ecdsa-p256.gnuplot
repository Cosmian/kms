set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'sign_ecdsa-p256.svg'
set title 'Throughput — sign/ecdsa-p256'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'sign_ecdsa-p256-5.27.1-pkcs11.dat' using 1:2 with linespoints lw 2 pt 7 title 'pkcs11'
