default:
	gcc main.c dynamicstr.c network.c -l curl -o vtotal
clean:
	rm vtotal
