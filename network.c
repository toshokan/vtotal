#include "network.h"
#include "dynamicstr.h"

char *send_file(char *apikey, char *filename){
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
		return NULL;
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
			return NULL;
		} else {
			//printf("We received %lu bytes. \n Here they are:\n%s\n", (long)data.size, data.str);
		}
		char *resource_str = parse_response(&data, "example");

		free(data.str);
		curl_easy_cleanup(curl);
		curl_formfree(formpost);
		return resource_str;
	}
}

char *parse_response(struct dynamic_str *data, char *filename){
	char *tag = "\"resource\": \"";
	char *str_begin = data->str;
	int res_begin_pos = strstr(str_begin, tag) + strlen(tag) - str_begin;
	char *resource = strndup(&str_begin[res_begin_pos], 64);
}

