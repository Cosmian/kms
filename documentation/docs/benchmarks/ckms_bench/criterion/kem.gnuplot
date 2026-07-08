set terminal svg size 2000,600 enhanced font 'Helvetica,12'
set output 'kem.svg'
set title 'Key Encapsulation (KEM)'
set grid
set ylabel 'Time (µs)'
set style data boxes
set style fill solid 0.7 border -1
set boxwidth 0.800
set grid ytics
set key top right
set xtics rotate by -30
set xtics ("configurable/decapsulate/ML-KEM-512" 0, "configurable/decapsulate/ML-KEM-512/P-256" 1, "configurable/decapsulate/ML-KEM-512/X25519" 2, "configurable/decapsulate/ML-KEM-768" 3, "configurable/decapsulate/ML-KEM-768/P-256" 4, "configurable/decapsulate/ML-KEM-768/X25519" 5, "configurable/encapsulate/ML-KEM-512" 6, "configurable/encapsulate/ML-KEM-512/P-256" 7, "configurable/encapsulate/ML-KEM-512/X25519" 8, "configurable/encapsulate/ML-KEM-768" 9, "configurable/encapsulate/ML-KEM-768/P-256" 10, "configurable/encapsulate/ML-KEM-768/X25519" 11, "pqc/decapsulate/ML-KEM-1024" 12, "pqc/decapsulate/ML-KEM-512" 13, "pqc/decapsulate/ML-KEM-768" 14, "pqc/decapsulate/X25519MLKEM768" 15, "pqc/decapsulate/X448MLKEM1024" 16, "pqc/encapsulate/ML-KEM-1024" 17, "pqc/encapsulate/ML-KEM-512" 18, "pqc/encapsulate/ML-KEM-768" 19, "pqc/encapsulate/X25519MLKEM768" 20, "pqc/encapsulate/X448MLKEM1024" 21)
plot 'kem.dat' using ($1+0.000):2 with boxes lw 1 title 'ttlv-json'
