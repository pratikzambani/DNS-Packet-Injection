dnsinject: dnsinject.c
					gcc dnsinject.c -o dnsinject -lpcap -lnet -lresolv

clean:
			rm -f *.o *.out dnsinject
