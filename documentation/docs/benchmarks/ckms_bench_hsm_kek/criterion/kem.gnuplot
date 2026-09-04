set terminal svg size 1200,600 enhanced font 'Helvetica,12'
set output 'kem.svg'
set title 'Key Encapsulation (KEM)'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.400
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("pqc/decapsulate/ML-KEM-512" 0, "pqc/encapsulate/ML-KEM-512" 1, "pqc/encapsulate/ML-KEM-768" 2)
plot 'kem.dat' using ($1+-0.200):2 with boxes lw 1 title 'ttlv-json', \
     'kem.dat' using ($1+0.200):3 with boxes lw 1 title 'ttlv-bytes'
