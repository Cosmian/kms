set terminal svg size 1000,500 enhanced font 'Helvetica,12'
set output 'hsm_sign-verify_eddsa-ed448.svg'
set title 'Throughput — hsm/sign-verify/eddsa-ed448'
set grid
set xlabel 'Concurrency'
set ylabel 'Requests/s'
set key top left
plot 'hsm_sign-verify_eddsa-ed448-5.27.0-ttlv-json.dat' using 1:2 with linespoints lw 2 pt 7 title 'ttlv-json'
