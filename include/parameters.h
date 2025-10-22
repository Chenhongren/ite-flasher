/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#ifndef PARAMETERS_H_
#define PARAMETERS_H_

enum update_flags {
	FLAG_SKIP_CHECK_STAGE = 0,
	FLAG_SKIP_VERIFY_STAGE,
	FLAG_USE_SPI,
	FLAG_ERASE_STAGE_ONLY,
	FLAG_DEBUG_MODE_ENABLE,
};

static int flags;

#endif /* PARAMETERS_H_ */
