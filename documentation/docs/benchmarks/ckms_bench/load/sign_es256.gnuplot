set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'sign_es256.svg'
set title 'Throughput — sign/es256'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'sign_es256-5.24.0-jose.dat' using 1:2 with linespoints lw 2 pt 7 title 'jose'
