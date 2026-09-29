set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'key-creation_aes-sym.svg'
set title 'Throughput — key-creation/aes-sym'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'key-creation_aes-sym-5.24.0-ttlv-json.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-json'
