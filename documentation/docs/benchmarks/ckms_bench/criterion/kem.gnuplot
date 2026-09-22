set terminal svg size 2000,600 enhanced font 'Helvetica,12'
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
set xtics ("configurable/decapsulate/ML-KEM-512" 0, "configurable/decapsulate/ML-KEM-768" 1, "configurable/encapsulate/ML-KEM-512" 2, "configurable/encapsulate/ML-KEM-768" 3, "pqc/decapsulate/ML-KEM-512" 4, "pqc/decapsulate/ML-KEM-768" 5, "pqc/encapsulate/ML-KEM-512" 6, "pqc/encapsulate/ML-KEM-768" 7)
plot 'kem.dat' using ($1+-0.200):2 with boxes lw 1 title 'ttlv-json', \
     'kem.dat' using ($1+0.200):3 with boxes lw 1 title 'ttlv-bytes'
