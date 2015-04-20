EXEC=main  #Nom du programme à modifier

all: ${EXEC}

${EXEC}:
	gcc -Wall -c *.c
	gcc -lpcap -lm -o Snifferpcap *.o






clean:
	rm -fr *.o

mrproper: clean
	rm -fr ${EXEC}

