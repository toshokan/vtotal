#include <stdio.h>
#include <stdlib.h>

#include "dynamicstr.h"
#include "network.h"

int main(int argc, char *argv[]){
	char apikey[65];
	FILE* fd = fopen("vconf/apikey","r");
	if (fd == NULL){
		fprintf(stderr, "There was a problem finding your API key. If you have not created one, do so and save it at the required path.\n");
		return EXIT_FAILURE;
	}
	if (fgets(apikey, 65, fd) == NULL){
		fprintf(stderr, "There was a problem with the format of your API key. Please check it and try again.\n");
		return EXIT_FAILURE;
	}
	if (argc == 1){
		fprintf(stderr, "Usage: ./a.out [filename]\n");
		return EXIT_FAILURE;
	}
	fclose(fd);
	fd = fopen(argv[1],"r");
	if (fd == NULL){
		fprintf(stderr, "Unable to load file: %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	char *resource_str = send_file(apikey, argv[1]);
	if (resource_str == NULL){
		return EXIT_FAILURE;
	}
	printf("Your file was successfully uploaded to VirusTotal. Check back later on resource: %s\n",resource_str);
}
