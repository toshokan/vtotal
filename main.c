#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

#include "dynamicstr.h"
#include "network.h"

bool write_resource_to_file(char *filename, char *resource);
int scan_mode(char *apikey, char *filename);
int result_mode(char *apikey, char *filename);
char *list_pending();

int main(int argc, char *argv[]){
	char apikey[65];
	FILE *fd = fopen("vconf/apikey","r");
	if (fd == NULL){
		fprintf(stderr, "There was a problem finding your API key. If you have not created one, do so and save it at the required path.\n");
		return EXIT_FAILURE;
	}
	if (fgets(apikey, 65, fd) == NULL){
		fprintf(stderr, "There was a problem with the format of your API key. Please check it and try again.\n");
		return EXIT_FAILURE;
	}
	switch (argc){
		case 1:
			fprintf(stderr, "Usage: ./a.out [filename]\n");
			return EXIT_FAILURE;
			break;
		case 2:
			switch (argv[1][0]){
				// Scan mode
				case 's':
					printf("scan mode\n");
					break;
				// Result mode
				case 'r':
					printf("result mode\n");
					break;
			}
			break;
		case 3:
			switch (argv[1][0]){
				// Scan mode with file
				case 's':
					return scan_mode(apikey, argv[2]);
					break;
				// Results list
				case 'r':
					if(strcmp(argv[2],"list")==0){
						char *fname = list_pending();
						return result_mode(apikey, fname);
					}
					printf("result mode, asked to check %s\n",argv[2]);
					return result_mode(apikey, argv[2]);
					break;
			}
			break;
	}
}

int scan_mode(char *apikey, char *filename){
	FILE *fd = fopen(filename,"r");
	if (fd == NULL){
		fprintf(stderr, "Unable to load file: %s\n", filename);
		return EXIT_FAILURE;
	}
	char *resource_str = send_file(apikey, filename);
	if (resource_str == NULL){
		return EXIT_FAILURE;
	}
	fclose(fd);
	bool s = write_resource_to_file(filename,resource_str);
	printf("Your file was successfully uploaded to VirusTotal. Check back later on resource: %s\n",resource_str);
	if(!s){
		printf("There was a problem writing resource to file. You will have to check manually.\n");
	}
}

bool write_resource_to_file(char *filename, char *resource){
	char filepath[1024];
	sprintf(filepath,"vpending/%s",filename);
	FILE *fd = fopen(filepath, "w+");
	if(!fd){
		return false;
	}
	fprintf(fd, "%s\n%s\n", filename, resource);
	fclose(fd);
	return true;
}

int result_mode(char *apikey, char *filename){
	char filepath[1024];
	sprintf(filepath,"vpending/%s",filename);
	FILE *fd = fopen(filepath, "r");
	if (!fd){
		fprintf(stderr, "Unable to load resource token: %s\n", filename);
		return EXIT_FAILURE;
	}
	char resource_str[65];
	int next_line = 0;
	while(next_line != 2){
		fscanf(fd,"%s", resource_str);
		next_line++;
	}
	struct scan_list *slist = get_results(apikey, resource_str);
	if (!slist){
		fprintf(stderr, "An error occurred retrieving results\n");
		return EXIT_FAILURE;
	}
	
	print_scan_list(slist);
	cleanup_scan_list(slist);
	free(slist);
}

char *list_pending(){
	DIR *d = opendir("vpending");
	struct dirent *dent;
	if(!d){
		fprintf(stderr, "Unable to open the \"vpending\" directory.");
		return NULL;
	}
	int current_file = 0; 
	struct dirent *files[10];
	printf("Here are the previous scans you might want to check on: \n");
	while(dent = readdir(d)){
		if(dent->d_type == DT_REG){
			char path[256];
			sprintf(path,"vpending/%s",dent->d_name);
			//char contents[1024]; 
			//FILE *fd = fopen(path,"r");
			// FIXME
			// Check ptr
			printf("\t[%i] %s\n",current_file,dent->d_name);
			//files[current_file] = fd;
			files[current_file] = dent;
			current_file++;
			//fgets(contents,1024,fd);
			//printf("%s\n\t%s\n",dent->d_name,contents);
			//contents[0] = '\0';
			//fclose(fd);
		}
	}
	int selection = -1;
	while(selection < 0 || selection > current_file - 1){
		printf("Choose a file to check on by entering its bracketed number: ");
		scanf("%d", &selection);
	}
	char *to_scan_file_name = strdup(files[selection]->d_name);
	return to_scan_file_name;
	for(int i = 0; i < current_file; i++){
		//closedir(files[i]);
	}

	closedir(d);
	return EXIT_SUCCESS;
}

