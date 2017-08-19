#include "network.h"
#include "dynamicstr.h"

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
