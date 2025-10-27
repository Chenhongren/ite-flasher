/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#ifndef PARAMETERS_H_
#define PARAMETERS_H_

/* TODO */
// #define VERSION "1.0.6.0.1"
#define ITE_FLASHER_VERSION "1.0.0"

enum update_flags {
	FLAG_SKIP_CHECK_STAGE = 0,
	FLAG_SKIP_VERIFY_STAGE,
	FLAG_USE_SPI,
	FLAG_ERASE_STAGE_ONLY,
	FLAG_DUMP_REGISTERS,
};

static bool debug_mode;

#endif /* PARAMETERS_H_ */
