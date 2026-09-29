set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'encrypt_aes-gcm.svg'
set title 'Throughput — encrypt/aes-gcm'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'encrypt_aes-gcm-5.24.0-jose.dat' using 1:2 with linespoints lw 2 pt 7 title 'jose', \
     'encrypt_aes-gcm-5.24.0-ttlv-bytes.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-bytes', \
     'encrypt_aes-gcm-5.24.0-ttlv-json.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-json'
