#ifndef VTOTAL_DYNAMICSTR_H
#define VTOTAL_DYNAMICSTR_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct dynamic_str {
	char *str;
	size_t size;
};

size_t dynamic_str_write(void *contents, size_t size, size_t nmemb, void *userp);

#endif
