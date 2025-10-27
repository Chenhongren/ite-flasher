/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#include <stdint.h>

#include "util.h"

void print_progress(const char *stage, int percent)
{
	LOG_RAW("\r%-16s : %3d%%", stage, percent);
	fflush(stdout);

	if (percent >= 100) {
		LOG_RAW("\n");
	}
}

void show_time(void)
{
	time_t now = time(NULL);
	char *time_str = ctime(&now);

	/* remove the trailing newline */
	time_str[strlen(time_str) - 1] = '\0';

	LOG_INFO("current time: %s", time_str);
}

void hexdump(const unsigned char *buffer, const size_t offset, size_t len)
{
	if (len > SIZE_MAX - offset) {
		LOG_WARN("%s: overflow (len %ld ->%ld)", __func__, len, SIZE_MAX - offset);
		len = SIZE_MAX - offset;
	}

	for (int i = 0; i < len; i++) {
		if ((i % 16 == 0)) {
			LOG_RAW(" %08llx :", (unsigned long long)(offset + i));
		}

		LOG_RAW(" %02x", buffer[i]);
		if ((i % 16) == 7) {
			LOG_RAW(" - ");
		}

		if ((i % 16) == 15) {
			LOG_RAW("\n");
		}
	}

	if (len % 16 != 0) {
		printf("\n");
	}
}
