/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include "util.h"
#include "libusb.h"
#include "ite_flasher.h"
#include "parameters.h"
#include "logging.h"

volatile sig_atomic_t keep_running = 1;

struct soc_info_t soc;

static void print_help(const char *progname)
{
	LOG_RAW("ITE EC Flasher Utility v%s\n", ITE_FLASHER_VERSION);
	LOG_RAW("Usage: %s [options]\n\n", progname);
	LOG_RAW("Options:\n");
	LOG_RAW("  -f, --filename <path>               Specify binary file to flash\n");
	LOG_RAW("  -s, --skip <check|verify>           Skip specified stage (check or verify)\n");
	LOG_RAW("  -u, --usespi                        Use SPI interface instead of default\n");
	LOG_RAW("  -e, --erase                         Erase and check flash only (no "
		"programming)\n");
	LOG_RAW("  -d, --debug_mode                    Enable debug messages\n");
	LOG_RAW("  -p, --dump_register <offset> [len]  Dump register(s) from device (max 256 "
		"bytes)\n");
	LOG_RAW("  -v, --version                       Show program version\n");
	LOG_RAW("  -h, --help                          Show this help message and exit\n\n");
	LOG_RAW("Examples:\n");
	LOG_RAW("  %s -f zephyr.bin -e\n", progname);
	LOG_RAW("  %s -f zephyr.bin -s check\n", progname);
	LOG_RAW("  %s -p 0x2085              # Dump one register\n", progname);
	LOG_RAW("  %s -p 0x2085 0x10         # Dump 16 registers\n", progname);
}

static void signal_handler(int signum)
{
	if (signum == SIGINT) {
		LOG_WARN("ite-flasher exits after completing this stage...");
		keep_running = 0;
	}
}

static void print_parameters(const int flags)
{
	char intfs[8];

	LOG_INFO("-------------------------------");
	if (flags & BIT(FLAG_USE_SPI)) {
		snprintf(intfs, sizeof(intfs), "spi");
	} else {
		snprintf(intfs, sizeof(intfs), "i2c");
	}
	LOG_INFO("update firmware via %s interface", intfs);

	if (debug_mode) {
		LOG_INFO("debug mode is enabled");
	}

	if (flags & BIT(FLAG_ERASE_STAGE_ONLY)) {
		LOG_INFO("erase stage only");
		goto out;
	}

	if (flags & (BIT(FLAG_SKIP_CHECK_STAGE) | BIT(FLAG_SKIP_VERIFY_STAGE))) {
		char skip_stages[32] = {0};
		int idx = 0;

		if (flags & BIT(FLAG_SKIP_CHECK_STAGE)) {
			idx += snprintf(skip_stages + idx, sizeof(skip_stages) - idx, "check ");
		}
		if (flags & BIT(FLAG_SKIP_VERIFY_STAGE)) {
			idx += snprintf(skip_stages + idx, sizeof(skip_stages) - idx, "verify ");
		}
		if (idx > 0) {
			LOG_INFO("Skip stages: %s", skip_stages);
		} else {
			LOG_WARN("No skip stages specified");
		}
	}

out:
	LOG_INFO("-------------------------------\n");
}

int main(int argc, char **argv)
{
	int option_index = 0;
	int c;
	char *filename = NULL;
	char *optstring = "f:s:p:uedvh";
	const struct option long_options[] = {{"filename", required_argument, NULL, 'f'},
					      {"skip", required_argument, NULL, 's'},
					      {"usespi", no_argument, NULL, 'u'},
					      {"erase", no_argument, NULL, 'e'},
					      {"debug_mode", no_argument, NULL, 'd'},
					      {"dump_register", required_argument, NULL, 'p'},
					      {"version", no_argument, NULL, 'v'},
					      {"help", no_argument, NULL, 'h'},
					      {0, 0, 0, 0}};
	static int ret, flags;
	uint32_t dump_reg_offset = 0;
	uint16_t dump_reg_len = 1;

	while (1) {
		c = getopt_long(argc, argv, optstring, long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'd':
			debug_mode = true;
			break;
		case 'f':
			filename = optarg;
			break;
		case 's':
			if (strcmp(optarg, "check") == 0) {
				flags |= BIT(FLAG_SKIP_CHECK_STAGE);
			}
			if (strcmp(optarg, "verify") == 0) {
				flags |= BIT(FLAG_SKIP_VERIFY_STAGE);
			}
			break;
		case 'u':
			flags |= BIT(FLAG_USE_SPI);
			break;
		case 'e':
			flags |= BIT(FLAG_ERASE_STAGE_ONLY);
			break;
		case 'p':
			dump_reg_offset = strtoul(optarg, NULL, 0);
			if (dump_reg_offset > 0xFFFF) {
				LOG_ERR("invalid offset 0x%08x(> 0xFFFF)", dump_reg_offset);
				return -EINVAL;
			}

			if (optind < argc && argv[optind][0] != '-') {
				dump_reg_len = strtoul(argv[optind], NULL, 0);
				optind++; // consume it
			}
			flags |= BIT(FLAG_DUMP_REGISTERS);
			break;
		case 'h':
			__attribute__((fallthrough));
		default:
			print_help(argv[0]);
			return -EINVAL;
		}
	}

	if (optind < argc) {
		LOG_ERR("unexpected argument '%s'\n", argv[optind]);
		print_help(argv[0]);
		return -EINVAL;
	}

	LOG_INFO("ITE EC Flasher Utility v%s", ITE_FLASHER_VERSION);

	print_parameters(flags);

	interface_initialization(USE_SPI(flags));

	show_time();

	if (!filename) {
		LOG_ERR("filename is null");
		return -ENOENT;
	}

	ret = init_file(filename);
	if (ret) {
		return ret;
	}

	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		LOG_ERR("failed to register signal handler\n");
		return -EINVAL;
	}

	ret = init_usb_device(ITE_USB_VID, ITE_USB_PID);
	if (ret) {
		goto out;
	}

	if ((flags & BIT(FLAG_DUMP_REGISTERS))) {
		uint8_t reg_val[(dump_reg_len > 0x100) ? 0x100 : dump_reg_len];

		if (dump_reg_len > 0x100) {
			LOG_WARN("support dumping up to 256 registers at one time");
			dump_reg_len = 0x100;
		}

		LOG_RAW("dump request: offset 0x%06x, len %u\n", 0xF00000 + dump_reg_offset,
			dump_reg_len);
		for (int i = 0; i < dump_reg_len; i++) {
			ret = read_register(dump_reg_offset + i, &reg_val[i]);
			if (ret) {
				LOG_INFO("failed to read offset[0x%x]", dump_reg_offset + i);
				goto out;
			}
		}
		hexdump(reg_val, 0, dump_reg_len);

		LOG_WARN("flash programming is skipped if dump is requested");
		ret = 0;
		goto out;
	}

	/* init */
	if (flags & BIT(FLAG_USE_SPI)) {
		ret = init_dlb4_spi();
	} else {
		int retries = 0;

		do {
			ret = init_dlb4_i2c();
			if (ret) {
				goto out;
			}

			if (soc.chip_id[0] != 0) {
				break;
			}

			fflush(stdout);
		} while (retries++ < 100 && keep_running == 1);

		if (soc.chip_id[0] == 0) {
			LOG_ERR("failed to get chip id. please re-run the program");
			ret = -ENXIO;
			goto out;
		}
	}

	show_itedlb4(USE_SPI(flags));

	/* erase stage */
	ret = flash_erase(USE_SPI(flags));
	if (ret) {
		goto out;
	}

	if (!keep_running) {
		ret = 0;
		goto out;
	}

	/* check stage */
	if (!(flags & BIT(FLAG_SKIP_CHECK_STAGE))) {
		ret = flash_check();
		if (ret) {
			goto out;
		}
	}

	if (flags & BIT(FLAG_ERASE_STAGE_ONLY) || !keep_running) {
		ret = 0;
		goto out;
	}

	/* program stage */
	ret = flash_program();
	if (ret) {
		goto out;
	}

	if (!keep_running) {
		ret = 0;
		goto out;
	}

	/* verify stage */
	if (!(flags & BIT(FLAG_SKIP_VERIFY_STAGE))) {
		ret = flash_verify();
		if (ret) {
			goto out;
		}
	}

	if (!keep_running) {
		ret = 0;
		goto out;
	}

	enable_qe_bit_and_reset_ec();

out:
	release_usb_device();
	free_write_read_buffer();
	show_time();

	return ret;
}
