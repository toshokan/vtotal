#include "network.h"
#include "dynamicstr.h"

void parse_scan_results(struct scan_list *slist, struct dynamic_str *data);

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

struct scan_list *get_results(char *apikey, char *resource){
	struct dynamic_str data;
	data.str = malloc(1);
	data.size = 0;

	char post_data[146];
	sprintf(post_data, "apikey=%s&resource=%s", apikey, resource);

	CURLcode res;

	CURL *curl = curl_easy_init();
	if (!curl){
		fprintf(stderr, "Failed to initialize networking.\n");
		//FIXME
		return NULL;
	} else {
		curl_easy_setopt(curl, CURLOPT_URL, "https://www.virustotal.com/vtapi/v2/file/report");
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dynamic_str_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&data);

		res = curl_easy_perform(curl);

		if (res != CURLE_OK){
			fprintf(stderr, "Failed to perform curl operation!: %s\n", curl_easy_strerror(res));
			return NULL;
		} else if ((long)data.size < 1){
			fprintf(stderr, "The operation succeeded, but we didn't get any data back. You probably made too many queries with your API key.\n");
			return NULL;
		} 

		struct scan_list *slist = malloc(sizeof(struct scan_list));
		slist->size = 0;
		parse_scan_results(slist, &data);

		return slist;

		curl_easy_cleanup(curl);
		return NULL;

	}
}

char *parse_response(struct dynamic_str *data, char *filename){
	char *tag = "\"resource\": \"";
	char *str_begin = data->str;
	int res_begin_pos = strstr(str_begin, tag) + strlen(tag) - str_begin;
	char *resource = strndup(&str_begin[res_begin_pos], 64);
}

void parse_scan_results(struct scan_list *slist, struct dynamic_str *data){
	char *keywords[] = {
		"\"scans\": {\"",
		"\"detected\": ",
		"\"version\": \"",
		"\"result\": ",
		"\"update\": \"",
	};
	char *str_begin = data->str;
	int pos_fq = strstr(str_begin, keywords[0]) + strlen(keywords[0]) - str_begin;
	int pos_endq = 0;
	bool done = false;
	while(!done){
		struct scan_list_entry *ent = malloc(sizeof(struct scan_list_entry));
		pos_endq = strstr(&str_begin[pos_fq], "\"") - str_begin;
		ent->name = strndup(&str_begin[pos_fq], pos_endq - pos_fq);

		pos_fq = strstr(&str_begin[pos_endq], keywords[1]) + strlen(keywords[1]) - str_begin;
		if (str_begin[pos_fq] == 'f'){
			ent->detected = false;
		} else {
			ent->detected = true;
		}

		pos_fq = strstr(&str_begin[pos_endq], keywords[2]) + strlen(keywords[2]) - str_begin;
		pos_endq = strstr(&str_begin[pos_fq], "\"") - str_begin;
		ent->version = strndup(&str_begin[pos_fq], pos_endq - pos_fq);

		pos_fq = strstr(&str_begin[pos_endq], keywords[3]) + strlen(keywords[3]) - str_begin;
		if (str_begin[pos_fq] == 'n'){
			ent->result = strdup("null");
		} else {
			pos_endq = strstr(&str_begin[pos_fq], "\"") - str_begin;
			ent->result = strndup(&str_begin[pos_fq], pos_endq - pos_fq);
		}

		pos_fq = strstr(&str_begin[pos_endq], keywords[4]) + strlen(keywords[4]) - str_begin;
		pos_endq = strstr(&str_begin[pos_fq], "\"") - str_begin;
		ent->update = strndup(&str_begin[pos_fq], pos_endq - pos_fq);

		slist->entries[slist->size] = ent;
		slist->size++;

		//printf("%s %d %s %s %s\n", ent->name, ent->detected, ent->version, ent->result, ent->update);
		
		if(pos_endq + 2 < data->size && str_begin[pos_endq+2] == ','){
			pos_fq = strstr(&str_begin[pos_endq + 1], "\"") + 1 - str_begin;
		} else {
			done = true;
		}
	}
}

void cleanup_scan_list(struct scan_list *slist){
	for(int i = 0; i < slist->size; i++){
		free(slist->entries[i]->name);
		free(slist->entries[i]->version);
		free(slist->entries[i]->result);
		free(slist->entries[i]->update);
		free(slist->entries[i]);
	}
}

void print_scan_list(struct scan_list *slist){
	for(int i = 0; i < slist->size; i++){
		printf("%s\n\tDetected: %s\n\tVersion: %s\n\tResult: %s\n\tUpdated: %s\n\t\n",
				slist->entries[i]->name,
				slist->entries[i]->detected == true ? "true" : "false",
				slist->entries[i]->version,
				slist->entries[i]->result,
				slist->entries[i]->update);
	}
}
