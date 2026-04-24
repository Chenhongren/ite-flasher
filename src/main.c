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

#define MONITOR_MIN_MSEC     10
#define MONITOR_DEFAULT_MSEC 1000
#define MONITOR_MAX_MSEC     10000

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
	LOG_RAW("  -w, --write <offset> <value>        Write value to register at offset\n");
	LOG_RAW("                                      (value: 1 byte, max 0xFF)\n");
	LOG_RAW("  -m, --monitor [ms]                  Enable monitoring (optional value in ms)\n");
	LOG_RAW("                                      Default: %d, Range: %d-%d\n",
		MONITOR_DEFAULT_MSEC, MONITOR_MIN_MSEC, MONITOR_MAX_MSEC);
	LOG_RAW("  -v, --version                       Show program version\n");
	LOG_RAW("  -h, --help                          Show this help message and exit\n\n");
	LOG_RAW("Examples:\n");
	LOG_RAW("  %s -f zephyr.bin -e\n", progname);
	LOG_RAW("  %s -f zephyr.bin -s check\n", progname);
	LOG_RAW("  %s -p 0x2085              # Dump one register\n", progname);
	LOG_RAW("  %s -p 0x2085 0x10         # Dump 16 registers\n", progname);
	LOG_RAW("  %s -w 0x1610 0x40         # Write 0x40 to register 0xF01610\n", progname);
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
	if (USE_SPI(flags)) {
		snprintf(intfs, sizeof(intfs), "spi");
	} else {
		snprintf(intfs, sizeof(intfs), "i2c");
	}
	LOG_INFO("update firmware via %s interface", intfs);

	if (debug_mode) {
		LOG_INFO("debug mode is enabled");
	}

	if (GET_BIT(flags, FLAG_DUMP_REGISTERS)) {
		if (GET_BIT(flags, FLAG_MONITOR_REGISTERS)) {
			LOG_INFO("monitor and dump flags are enabled");
		} else {
			LOG_INFO("dump flag is enabled");
		}
		goto out;
	}

	if (GET_BIT(flags, FLAG_ERASE_STAGE_ONLY)) {
		LOG_INFO("erase stage only");
		goto out;
	}

	if (flags & (BIT(FLAG_SKIP_CHECK_STAGE) | BIT(FLAG_SKIP_VERIFY_STAGE))) {
		char skip_stages[32] = {0};
		int idx = 0;

		if (GET_BIT(flags, FLAG_SKIP_CHECK_STAGE)) {
			idx += snprintf(skip_stages + idx, sizeof(skip_stages) - idx, "check ");
		}
		if (GET_BIT(flags, FLAG_SKIP_VERIFY_STAGE)) {
			idx += snprintf(skip_stages + idx, sizeof(skip_stages) - idx, "verify ");
		}
		if (idx > 0) {
			LOG_INFO("skip stages: %s", skip_stages);
		} else {
			LOG_WARN("no skip stages specified");
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
	char *optstring = "f:s:p:w:m::uedvh";
	const struct option long_options[] = {{"filename", required_argument, NULL, 'f'},
					      {"skip", required_argument, NULL, 's'},
					      {"usespi", no_argument, NULL, 'u'},
					      {"erase", no_argument, NULL, 'e'},
					      {"debug_mode", no_argument, NULL, 'd'},
					      {"dump_register", required_argument, NULL, 'p'},
					      {"write", required_argument, NULL, 'w'},
					      {"monitor", optional_argument, NULL, 'm'},
					      {"version", no_argument, NULL, 'v'},
					      {"help", no_argument, NULL, 'h'},
					      {0, 0, 0, 0}};
	static int ret, flags;
	uint32_t reg_offset = 0;
	uint16_t dump_reg_len = 1;
	uint8_t write_reg_value = 0;
	long monitor_ms = MONITOR_DEFAULT_MSEC;

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
				SET_BIT(flags, FLAG_SKIP_CHECK_STAGE);
			}
			if (strcmp(optarg, "verify") == 0) {
				SET_BIT(flags, FLAG_SKIP_VERIFY_STAGE);
			}
			break;
		case 'u':
			SET_BIT(flags, FLAG_USE_SPI);
			break;
		case 'e':
			SET_BIT(flags, FLAG_ERASE_STAGE_ONLY);
			break;
		case 'p':
			__attribute__((fallthrough));
		case 'w':
			reg_offset = strtoul(optarg, NULL, 0);
			if (reg_offset > 0xFFFF) {
				LOG_ERR("invalid offset 0x%08x(> 0xFFFF)\n", reg_offset);
				print_help(argv[0]);
				return -EINVAL;
			}
			if (c == 'p') {
				if (optind < argc && argv[optind][0] != '-') {
					dump_reg_len = strtoul(argv[optind], NULL, 0);
					optind++; // consume it
				}
				SET_BIT(flags, FLAG_DUMP_REGISTERS);
			} else {
				if (optind >= argc) {
					LOG_ERR("missing value for `--write`\n");
					print_help(argv[0]);
					return -EINVAL;
				}
				if (argv[optind][0] != '-') {
					write_reg_value = strtoul(argv[optind], NULL, 0);
					optind++;
				}
				SET_BIT(flags, FLAG_WRITE_REGISTER);
			}

			break;
		case 'm':
			if (optarg) {
				monitor_ms = strtol(optarg, NULL, 0);
			}

			if (monitor_ms < MONITOR_MIN_MSEC || monitor_ms > MONITOR_MAX_MSEC) {
				LOG_ERR("invalid monitor_ms(%ld ms), restore to default(1000 ms)",
					monitor_ms);
				monitor_ms = MONITOR_DEFAULT_MSEC;
			}
			SET_BIT(flags, FLAG_MONITOR_REGISTERS);
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

	if (GET_BIT(flags, FLAG_MONITOR_REGISTERS) && !GET_BIT(flags, FLAG_DUMP_REGISTERS)) {
		LOG_ERR("register: monitor flag is enabled but dump flag is null");
		ret = -EINVAL;
		goto out;
	}

	if (GET_BIT(flags, FLAG_WRITE_REGISTER)) {
		LOG_RAW("write request: offset 0x%06x, value 0x%x\n\n", 0xF00000 + reg_offset,
			write_reg_value);

		ret = send_specific_d2ec_command();
		if (ret) {
			LOG_ERR("failed to send specific d2ec command");
			goto out;
		}

		ret = write_register(reg_offset, write_reg_value);
		if (ret) {
			LOG_ERR("failed to write offset[0x%x]", reg_offset);
		}

		uint8_t reg_val_temp;

		ret = read_register(reg_offset, &reg_val_temp);
		if (ret) {
			LOG_ERR("failed to read offset[0x%x]", reg_offset);
		}

		if (reg_val_temp != write_reg_value) {
			LOG_ERR("failed to write offset[0x%x], cmp error (0x%x != 0x%x(exp.))",
				reg_offset, reg_val_temp, write_reg_value);
		}

		LOG_WARN("flash programming is skipped if write is requested");
		ret = 0;
		goto out;
	}

	if (GET_BIT(flags, FLAG_DUMP_REGISTERS)) {
		uint8_t reg_val[(dump_reg_len > 0x100) ? 0x100 : dump_reg_len];

		if (dump_reg_len > 0x100) {
			LOG_WARN("support dumping up to 256 registers at one time");
			dump_reg_len = 0x100;
		}

		LOG_RAW("dump request: offset 0x%06x, len %u\n", 0xF00000 + reg_offset,
			dump_reg_len);

		ret = send_specific_d2ec_command();
		if (ret) {
			LOG_ERR("failed to send specific d2ec command");
			goto out;
		}

		do {
			for (int i = 0; i < dump_reg_len; i++) {
				ret = read_register(reg_offset + i, &reg_val[i]);
				if (ret) {
					LOG_INFO("failed to read offset[0x%x]", reg_offset + i);
					goto out;
				}
			}
			hexdump(reg_val, 0, dump_reg_len);
			LOG_RAW("\n");
			msleep(monitor_ms);
		} while (keep_running && GET_BIT(flags, FLAG_MONITOR_REGISTERS));

		LOG_WARN("flash programming is skipped if dump is requested");
		ret = 0;
		goto out;
	}

	/* init */
	if (USE_SPI(flags)) {
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
	if (!(GET_BIT(flags, FLAG_SKIP_CHECK_STAGE))) {
		ret = flash_check();
		if (ret) {
			goto out;
		}
	}

	if (GET_BIT(flags, FLAG_ERASE_STAGE_ONLY) || !keep_running) {
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
	if (!(GET_BIT(flags, FLAG_SKIP_VERIFY_STAGE))) {
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
