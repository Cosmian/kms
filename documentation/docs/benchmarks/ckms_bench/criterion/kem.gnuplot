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
set xtics ("configurable/decapsulate/ML-KEM-512" 0, "configurable/decapsulate/ML-KEM-512/P-256" 1, "configurable/decapsulate/ML-KEM-768" 2, "configurable/decapsulate/ML-KEM-768/P-256" 3, "configurable/encapsulate/ML-KEM-512" 4, "configurable/encapsulate/ML-KEM-512/P-256" 5, "configurable/encapsulate/ML-KEM-768" 6, "configurable/encapsulate/ML-KEM-768/P-256" 7, "pqc/decapsulate/ML-KEM-1024" 8, "pqc/decapsulate/ML-KEM-512" 9, "pqc/decapsulate/ML-KEM-768" 10, "pqc/decapsulate/X25519MLKEM768" 11, "pqc/encapsulate/ML-KEM-1024" 12, "pqc/encapsulate/ML-KEM-512" 13, "pqc/encapsulate/ML-KEM-768" 14, "pqc/encapsulate/X25519MLKEM768" 15)
plot 'kem.dat' using ($1+-0.200):2 with boxes lw 1 title 'ttlv-json', \
     'kem.dat' using ($1+0.200):3 with boxes lw 1 title 'ttlv-bytes'
