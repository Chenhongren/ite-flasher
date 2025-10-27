/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#ifndef LOGGING_H_
#define LOGGING_H_

#include "util.h"
#include "parameters.h"

#define LOG_ERR(fmt, args...)                                                                      \
	if (debug_mode) {                                                                          \
		fprintf(stderr, "<error> %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stderr, "<error> " fmt "\n", ##args);                                      \
	}

#define LOG_WARN(fmt, args...)                                                                     \
	if (debug_mode) {                                                                          \
		fprintf(stdout, "<warn>  %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stdout, "<warn>  " fmt "\n", ##args);                                      \
	}

#define LOG_INFO(fmt, args...)                                                                     \
	if (debug_mode) {                                                                          \
		fprintf(stdout, "<info>  %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stdout, "<info>  " fmt "\n", ##args);                                      \
	}

#define LOG_DBG(fmt, args...)                                                                      \
	if (debug_mode) {                                                                          \
		fprintf(stdout, "<debug> %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stdout, "<debug> " fmt "\n", ##args);                                      \
	}

#define LOG_RAW(fmt, args...) fprintf(stdout, fmt, ##args)

#endif /* LOGGING_H_ */
