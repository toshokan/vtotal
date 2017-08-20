#ifndef VTOTAL_NETWORK_H
#define NETWORK_H

#include <curl/curl.h>

#include "dynamicstr.h"

char *send_file(char *apikey, char *filename);
char *parse_response(struct dynamic_str *data, char *filename);
char *get_results(char *apikey, char *resource);

#endif
