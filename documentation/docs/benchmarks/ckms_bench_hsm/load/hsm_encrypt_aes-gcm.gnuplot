set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'hsm_encrypt_aes-gcm.svg'
set title 'Throughput — hsm/encrypt/aes-gcm'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'hsm_encrypt_aes-gcm-5.27.0-ttlv-json.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-json'
