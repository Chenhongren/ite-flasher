/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#ifndef LOGGING_H_
#define LOGGING_H_

#include "parameters.h"

#define IS_DEBUG_MODE_ENABLED() (flags & BIT(FLAG_DEBUG_MODE_ENABLE))
#define LOG_ERR(fmt, args...)                                                                      \
	if (IS_DEBUG_MODE_ENABLED()) {                                                             \
		fprintf(stderr, "<error> %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stderr, "<error> " fmt "\n", ##args);                                      \
	}

#define LOG_WARN(fmt, args...)                                                                     \
	if (IS_DEBUG_MODE_ENABLED()) {                                                             \
		fprintf(stdout, "<warn>  %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stdout, "<warn>  " fmt "\n", ##args);                                      \
	}

#define LOG_INFO(fmt, args...)                                                                     \
	if (IS_DEBUG_MODE_ENABLED()) {                                                             \
		fprintf(stdout, "<info>  %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stdout, "<info>  " fmt "\n", ##args);                                      \
	}

#define LOG_DBG(fmt, args...)                                                                      \
	if (IS_DEBUG_MODE_ENABLED()) {                                                             \
		fprintf(stdout, "<debug> %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__,     \
			##args);                                                                   \
	} else {                                                                                   \
		fprintf(stdout, "<debug> " fmt "\n", ##args);                                      \
	}

#define LOG_RAW(fmt, args...) fprintf(stdout, fmt, ##args)

#endif /* LOGGING_H_ */
