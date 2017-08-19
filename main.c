#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

struct dynamic_str {
	char *str;
	size_t size;
};

void send_file(char *apikey, char *filename, char *buf);
size_t dynamic_str_write(void *contents, size_t size, size_t nmemb, void *userp);

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
	char buf[10240];
	send_file(apikey, argv[1], buf);
}

void send_file(char *apikey, char *filename, char *buf){
	struct dynamic_str data;
	data.str = malloc(1);
	data.size = 0;

	CURL *curl = curl_easy_init();
	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	CURLcode res;

	if (curl == NULL){
		fprintf(stderr, "Failed to initialize networking.\n");
		// FIXME
		// exit
		//return EXIT_FAILURE;
		return;
	} else {
		curl_formadd(&formpost,
					 &lastptr,
					 CURLFORM_COPYNAME, "apikey",
					 CURLFORM_COPYCONTENTS, apikey,
					 CURLFORM_END);

		curl_formadd(&formpost,
					 &lastptr,
					 CURLFORM_COPYNAME, "file",
					 CURLFORM_FILE, filename,
					 CURLFORM_END);

		curl_easy_setopt(curl, CURLOPT_URL, "https://www.virustotal.com/vtapi/v2/file/scan");
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dynamic_str_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK){
			fprintf(stderr, "failed to perform curl operation!: %s\n", curl_easy_strerror(res));
		} else {
			printf("We received %lu bytes. \n Here they are:\n%s\n", (long)data.size, data.str);
		}

		curl_easy_cleanup(curl);
		curl_formfree(formpost);
	}
}

size_t dynamic_str_write(void *contents, size_t size, size_t nmemb, void *userp){
	size_t bytes = size * nmemb;
	struct dynamic_str *data = (struct dynamic_str *)userp;
	data->str = realloc(data->str, data->size + bytes + 1);
	if(data->str == NULL){
		fprintf(stderr, "Problem allocating enough memory to hold curl response\n");
		return 0;
	}

	memcpy(&(data->str[data->size]), contents, bytes);
	data->size += bytes;
	data->str[data->size] = 0;

	return bytes;
}
