/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "logging.h"

#define BIT(nr) (1UL << (nr))

/* generate a contiguous bitmask from bit 'l' to bit 'h' (inclusive) */
#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#endif

/* extract field value defined by mask from x */
#define FIELD_GET(mask, x) (((x) & (mask)) >> (__builtin_ctzl(mask)))

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define BYTE_0(x) FIELD_GET(GENMASK(7, 0), x)
#define BYTE_1(x) FIELD_GET(GENMASK(15, 8), x)

#define SAFE_FREE_PTR(p)                                                                           \
	if (p) {                                                                                   \
		free(p);                                                                           \
		p = NULL;                                                                          \
	}

#define SAFE_CLOSE_FD(fd)                                                                          \
	if (fd) {                                                                                  \
		fclose(fd);                                                                        \
		fd = NULL;                                                                         \
	}

#define CHECK_RET(func_call)                                                                       \
	do {                                                                                       \
		int __ret = (func_call);                                                           \
		if (__ret)                                                                         \
			return __ret;                                                              \
	} while (0)

#define msleep(msecs)                                                                              \
	nanosleep(&(struct timespec){msecs / 1000, (msecs * 1000000) % 1000000000UL}, NULL);

#define USE_SPI(flag) ((flag) & BIT(FLAG_USE_SPI))

void print_progress(const char *stage, int percent);

void show_time(void);

void hexdump(const unsigned char *buffer, const size_t offset, size_t len);

#endif /* UTIL_H_ */
