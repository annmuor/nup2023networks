all:
	gcc lib.c -c -o lib.o
	gcc echat-server.c -c -o echat-server.o
	gcc echat-echo.c -c -o echat-echo.o
	gcc echat-getflag.c -c -o echat-getflag.o
	gcc echat-server.o lib.o -lpcap -o echat-server
	gcc echat-echo.o lib.o -lpcap -o echat-echo
	gcc echat-getflag.o lib.o -lpcap -o echat-getflag
