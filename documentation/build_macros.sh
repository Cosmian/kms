#!/bin/sh

awk -F":" 'NF == 2 {print "katex.\_\_defineMacro\(\"" $1 "\", \"" $2 "\"\)"}' macros.txt | sed 's/\\/\\\\/g' > docs/javascripts/macros.js
awk -F":" 'NF == 2 {print "\\newcommand{" $1 "\}\{" $2 "\}"}' macros.txt > pandoc/macros.tex