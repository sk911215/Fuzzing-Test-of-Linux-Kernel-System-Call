all:
	pdflatex fuzzing.tex
	bibtex fuzzing
	pdflatex fuzzing.tex
	pdflatex fuzzing.tex

clean:
	rm -f *.pdf *.ps *.dvi *.out *.log *.aux *.bbl *.blg *.pyg
