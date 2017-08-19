#include "dynamicstr.h"

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
