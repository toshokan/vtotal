#ifndef VTOTAL_NETWORK_H
#define VTOTAL_NETWORK_H

#include <curl/curl.h>
#include <stdbool.h>

#include "dynamicstr.h"

struct scan_list_entry {
	char *name;
	bool detected;
	char *version;
	char *result;
	char *update;
};

struct scan_list {
	struct scan_list_entry *entries[100];
	size_t size;
};

char *send_file(char *apikey, char *filename);
char *parse_response(struct dynamic_str *data, char *filename);
struct scan_list *get_results(char *apikey, char *resource);
void cleanup_scan_list(struct scan_list *slist);
void print_scan_list(struct scan_list *slist);

#endif
