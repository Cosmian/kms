set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'sign-verify_ecdsa-p256.svg'
set title 'Throughput — sign-verify/ecdsa-p256'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'sign-verify_ecdsa-p256-5.24.0-jose.dat' using 1:2 with linespoints lw 2 pt 7 title 'jose', \
     'sign-verify_ecdsa-p256-5.24.0-ttlv-bytes.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-bytes', \
     'sign-verify_ecdsa-p256-5.24.0-ttlv-json.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-json'
