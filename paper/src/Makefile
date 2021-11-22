CC=xelatex
FILE=main.tex

all: build

build:
	$(CC) $(FILE)
	$(CC) $(FILE)
	rm -rf main.{aux,log,toc,out}
	mv main.pdf ../build
