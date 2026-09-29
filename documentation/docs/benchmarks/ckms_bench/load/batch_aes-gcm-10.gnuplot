set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'batch_aes-gcm-10.svg'
set title 'Throughput — batch/aes-gcm-10'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'batch_aes-gcm-10-5.24.0-ttlv-json.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-json'
