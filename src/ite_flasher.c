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
#include <unistd.h>

#include "util.h"
#include "libusb.h"
#include "ite_flasher.h"
#include "parameters.h"
#include "logging.h"

struct flash_file_info_t file;
struct flash_info_t flash_info;
struct dbgr_code_t dbgr_code;
struct soc_dlb4_info_t soc_dlb4_info;

unsigned char *g_readbuf;
unsigned char *g_writebuf;

static int send_command(uint8_t *command, const unsigned int data_length, const uint8_t direction)
{
	int ret;
	int written_bytes;
	struct dlb4_cbw_t cbw;
	uint8_t buffer[32];

	cbw.dSignature = DLB4_CBW_SIGNATURE;
	cbw.dTag = rand();
	cbw.dDataLength = data_length;
	cbw.bmFlags = direction;
	cbw.bCBLength = DLB4_CBW_CBLength;
	memcpy(cbw.CB, command, cbw.bCBLength);
	memcpy(buffer, &cbw, sizeof(cbw));

	ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.out_ep,
				   (unsigned char *)&buffer, sizeof(cbw), &written_bytes, 1000);
	if (ret == LIBUSB_ERROR_PIPE) {
		libusb_clear_halt(soc_dlb4_info.handle, soc_dlb4_info.out_ep);
	}

	if (ret != LIBUSB_SUCCESS) {
		OUTPUT_LIBUSB_ERROR_STRING(ret);
		return ret;
	}

	if (written_bytes != sizeof(cbw)) {
		LOG_ERR("failed to write usb data(%d != %ld)", written_bytes, sizeof(cbw));
		return -EIO;
	}

	return 0;
}

static int read_dlb4_csw_signature(void)
{
	int ret;
	int read_bytes;
	struct dlb4_csw_t csw;
	uint8_t buffer[32];

	ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.in_ep,
				   (unsigned char *)&buffer, sizeof(csw), &read_bytes, 1000);
	if (ret != LIBUSB_SUCCESS) {
		OUTPUT_LIBUSB_ERROR_STRING(ret);
		return ret;
	}

	memcpy(&csw, buffer, sizeof(csw));
	if (read_bytes != sizeof(csw) || csw.dSignature != DLB4_CSW_SIGNATURE) {
		LOG_ERR("failed to read dlb4 csw signature:");
		if (read_bytes != sizeof(csw)) {
			LOG_ERR("  read byte: %d != %ld", read_bytes, sizeof(csw));
		}
		if (csw.dSignature != DLB4_CSW_SIGNATURE) {
			LOG_ERR("  signature: %x != %x", csw.dSignature, DLB4_CSW_SIGNATURE);
		}
		hexdump(buffer, 0, 32);
		return -EIO;
	}

	return 0;
}

static int read_from_itedev(uint8_t *command, unsigned char *read_data, unsigned int bytes)
{
	int bytesRead;
	int ret;

	if (!command || !read_data || bytes == 0) {
		return -EINVAL;
	}

	/* send command before reading data */
	ret = send_command(command, bytes, LIBUSB_ENDPOINT_IN);
	if (ret) {
		return ret;
	}

	bytesRead = 0;
	ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.in_ep, read_data, bytes,
				   &bytesRead, 5000);

	if (ret == LIBUSB_ERROR_PIPE) {
		libusb_clear_halt(soc_dlb4_info.handle, soc_dlb4_info.out_ep);
	}

	if (ret != LIBUSB_SUCCESS) {
		OUTPUT_LIBUSB_ERROR_STRING(ret);
		return ret;
	}

	return read_dlb4_csw_signature();
}

static int write_to_itedev(uint8_t *command, unsigned char *write_data, unsigned int bytes)
{
	int bytesWritten;
	int ret;

	if (!command || !write_data || bytes == 0) {
		return -EINVAL;
	}

	/* send command before writing data */
	ret = send_command(command, bytes, LIBUSB_ENDPOINT_OUT);
	if (ret) {
		return ret;
	}

	ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.out_ep, write_data, bytes,
				   &bytesWritten, 5000);
	if (ret == LIBUSB_ERROR_PIPE) {
		libusb_clear_halt(soc_dlb4_info.handle, soc_dlb4_info.out_ep);
	}
	if (ret != LIBUSB_SUCCESS) {
		OUTPUT_LIBUSB_ERROR_STRING(ret);
		return ret;
	}

	return read_dlb4_csw_signature();
}

int excute_command(struct dlb4_operation_t *cmd)
{
	int ret;
	unsigned char cmdbuf[DLB4_CBW_CBLength];

	if (!cmd) {
		return -EINVAL;
	}

	cmdbuf[0] = cmd->op_code;
	cmdbuf[1] = cmd->fun_code;
	cmdbuf[2] = cmd->p1;
	cmdbuf[3] = cmd->p2;
	cmdbuf[4] = cmd->p3;
	cmdbuf[5] = cmd->p4;
	cmdbuf[6] = cmd->p5;
	cmdbuf[7] = cmd->p6;
	cmdbuf[8] = cmd->p7;

	if (cmd->direction == ITE_DIR_IN) {
		ret = read_from_itedev(cmdbuf, cmd->buffer, cmd->size);
	} else if (cmd->direction == ITE_DIR_OUT) {
		ret = write_to_itedev(cmdbuf, cmd->buffer, cmd->size);
	} else {
		LOG_ERR("unknown command direction");
		ret = -EINVAL;
	}

	return ret;
}

/*
 * pin      : 1 => C1
 *            2 => C2
 *            3 => H1
 *            4 => H2
 * pin_data : 0 => ALT
 *            1 => OUTPUT
 *            2 => HIGH
 *            3 => LOW
 */
static int dlb4_set_gpio(const uint8_t pin, const uint8_t pin_data)
{
	struct dlb4_operation_t cmdParam;
	unsigned char data[2];

	data[0] = pin;
	data[1] = pin_data;

	cmdParam.op_code = OP_FW_CTRL;
	cmdParam.fun_code = FW_CTL_FUN_CODE_SET_GPIO;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = 4;

	return excute_command(&cmdParam);
}

static int get_dlb4_fw_version(uint8_t *firmware_version)
{
	int ret;
	unsigned char data[4];
	struct dlb4_operation_t cmdParam;

	if (!firmware_version) {
		return -EINVAL;
	}

	cmdParam.op_code = OP_FW_CTRL;
	cmdParam.fun_code = FW_CTL_FUN_CODE_READ_FW_VER;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = sizeof(data);

	ret = excute_command(&cmdParam);
	memcpy(firmware_version, data, sizeof(data));

	return ret;
}

int get_chip_id(uint8_t *chip_id)
{
	int ret;
	unsigned char data[3];
	struct dlb4_operation_t cmdParam;

	if (!chip_id) {
		return -EINVAL;
	}

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = DBGR_FUN_CODE_CHIPID_READ;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = sizeof(data);

	ret = excute_command(&cmdParam);
	if (!ret) {
		memcpy(chip_id, data, sizeof(data));
	}

	return ret;
}

static int get_flash_id(uint8_t *flash_id, const uint8_t mode)
{
	int ret;
	unsigned char data[5];
	struct dlb4_operation_t cmdParam;

	if (!flash_id) {
		return -EINVAL;
	}

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = dbgr_code.fun_code.flashid;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = sizeof(data);
	cmdParam.p1 = mode;

	ret = excute_command(&cmdParam);
	if (!ret) {
		memcpy(flash_id, data, sizeof(data));
	}

	return ret;
}

static int start_d2ec(const uint8_t mode)
{
	unsigned char data[1];
	struct dlb4_operation_t cmdParam;

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = DBGR_FUN_CODE_START_D2EC;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = sizeof(data);
	cmdParam.p1 = mode;

	return excute_command(&cmdParam);
}

static int run_ctrl(const uint8_t p1, const uint8_t p2, const uint8_t p3)
{
	unsigned char data[1];
	struct dlb4_operation_t cmdParam;

	data[0] = 0x24; /* dummy test */
	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = DBGR_FUN_CODE_RUN_CTRL;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = sizeof(data);
	cmdParam.p1 = p1;
	cmdParam.p2 = p2;
	cmdParam.p3 = p3;

	return excute_command(&cmdParam);
}

static int rw_dbgr_command_set(const uint8_t rw, const uint8_t cmd, uint8_t *value)
{
	int ret;
	unsigned char data[1];
	struct dlb4_operation_t cmdParam;

	if (!value) {
		return -EINVAL;
	}

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = DBGR_FUN_CODE_DBGR_CMD_SET;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = sizeof(data);
	cmdParam.p1 = rw;
	cmdParam.p2 = cmd;
	cmdParam.p3 = *value;

	ret = excute_command(&cmdParam);
	if (rw == 0) {
		*value = data[0];
	}

	return ret;
}

static int write_register(const uint16_t offset, const uint8_t data)
{
	unsigned char local[1];
	struct dlb4_operation_t cmdParam;

	local[0] = data;

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = DBGR_FUN_CODE_WRITE_REG;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = local;
	cmdParam.size = sizeof(local);
	cmdParam.p1 = BYTE_1(offset);
	cmdParam.p2 = BYTE_0(offset);
	cmdParam.p7 = 0xf0;

	return excute_command(&cmdParam);
}

static int update_non_sst_flash_sataus(const uint8_t byte_count, const uint8_t s1, const uint8_t s2)
{
	int ret;
	unsigned char local[byte_count];
	struct dlb4_operation_t cmdParam;

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = DBGR_FUN_CODE_FLASH_R_SPI_STATUS;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = local;
	cmdParam.size = byte_count;
	cmdParam.p1 = byte_count;
	cmdParam.p2 = s1;
	cmdParam.p3 = s2;

	ret = excute_command(&cmdParam);
	LOG_RAW("\nProtect Status: mode=%x data=%x %x\n", byte_count, local[0], local[1]);

	return ret;
}

int read_register(const uint16_t offset, uint8_t *data)
{
	int ret;
	unsigned char local[1];
	struct dlb4_operation_t cmdParam;

	if (!data) {
		return -EINVAL;
	}

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = DBGR_FUN_CODE_READ_REG;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = local;
	cmdParam.size = sizeof(local);
	cmdParam.p1 = BYTE_1(offset);
	cmdParam.p2 = BYTE_0(offset);
	cmdParam.p7 = 0xf0;

	ret = excute_command(&cmdParam);
	if (!ret) {
		memcpy(data, local, sizeof(local));
	}

	return ret;
}

static int eraseflash(const int block_num, const uint8_t sector_num, const uint8_t erase_mode,
		      const uint8_t erase_type)
{
	unsigned char local[1];
	struct dlb4_operation_t cmdParam;

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = dbgr_code.fun_code.erase;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = local;
	cmdParam.size = sizeof(local);
	cmdParam.p1 = erase_mode;
	cmdParam.p2 = erase_type;
	cmdParam.p3 = (block_num % 256);
	cmdParam.p4 = sector_num;
	cmdParam.p5 = (block_num / 256);
	cmdParam.p6 = 0; /* switch rom */

	return excute_command(&cmdParam);
}

static int readflash(const int block_num, const uint8_t command_mode, uint8_t *data)
{
	struct dlb4_operation_t cmdParam;

	if (!data) {
		return -EINVAL;
	}

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = dbgr_code.fun_code.read;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = FILE_SIZE_64K;
	cmdParam.p1 = block_num % 256;   /* BA */
	cmdParam.p2 = command_mode;      /* read mode */
	cmdParam.p3 = 0;                 /* dummy */
	cmdParam.p4 = 0;                 /* dummy */
	cmdParam.p5 = (block_num / 256); /* EBA */
	cmdParam.p6 = 0;                 /* switch rom */

	return excute_command(&cmdParam);
}

static int writeflash(const int block_num, const uint8_t command_mode, const uint8_t program_type,
		      uint8_t *data, const int len)
{
	struct dlb4_operation_t cmdParam;

	if (!data || len <= 0) {
		return -EINVAL;
	}

	cmdParam.op_code = dbgr_code.op;
	cmdParam.fun_code = dbgr_code.fun_code.write;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = len;
	cmdParam.p1 = command_mode;
	cmdParam.p2 = block_num % 256;
	cmdParam.p3 = program_type;
	cmdParam.p5 = (block_num / 256); /* EBA */
	cmdParam.p6 = 0;                 /* switch rom */

	return excute_command(&cmdParam);
}

int flash_erase(const bool use_spi)
{
	int ret;
	const uint32_t blocks = file.block_num;
	const int erase_mode = flash_info.erase_mode;
	const int erase_type = flash_info.erase_type;

	if (use_spi) {
		ret = eraseflash(blocks, 4, erase_mode, erase_type);
		if (ret) {
			LOG_ERR("SPI erase failed");
			return ret;
		}
		print_progress("Erasing", 100);
		return 0;
	}

	for (int i = 0; i < blocks; i++) {
		for (int sector = 0; sector < 16; sector++) {
			int address = (sector << 4) + 0xF;

			ret = eraseflash(i, address, erase_mode, erase_type);
			if (ret) {
				LOG_ERR("erase failed at block %d sector %d", i, sector);
				return ret;
			}
		}
		print_progress("Erasing", (i + 1) * 100 / blocks);
	}

	return 0;
}

int flash_check(void)
{
	int ret;
	uint32_t total_size = file.size;
	uint32_t block_size = FILE_SIZE_64K;
	uint32_t checked = 0;

	for (int i = 0; i < file.block_num; i++) {
		uint32_t cur_size = MIN(block_size, total_size - checked);

		ret = readflash(i, flash_info.read_mode, g_readbuf);
		if (ret) {
			LOG_ERR("failed to read flash at block %d", i);
			return ret;
		}

		for (uint32_t j = 0; j < cur_size; j++) {
			if (g_readbuf[j] != 0xFF) {
				uint32_t offset = checked + j;
				LOG_ERR("failed to check: offset[%x]=%x not 0xff", offset,
					g_readbuf[j]);
				hexdump(g_readbuf + j, offset, 64);
				return -EIO;
			}
		}

		checked += cur_size;
		print_progress("Checking", checked * 100 / total_size);
	}

	return 0;
}

int flash_program(void)
{
	int ret;
	uint32_t total_size = file.size;
	uint32_t block_size = FILE_SIZE_64K;
	uint32_t written = 0;

	for (int i = 0; i < file.block_num; i++) {
		uint32_t cur_size = MIN(block_size, total_size - written);
		uint8_t *buf = g_writebuf + written;

		ret = writeflash(i, flash_info.write_mode, flash_info.write_type, buf, cur_size);
		if (ret) {
			LOG_ERR("failed to write flash at block %d", i);
			return ret;
		}

		written += cur_size;
		print_progress("Programming", written * 100 / total_size);
	}

	return 0;
}

int flash_verify(void)
{
	int ret;
	uint32_t total_size = file.size;
	uint32_t block_size = FILE_SIZE_64K;
	uint32_t verified = 0;

	for (int i = 0; i < file.block_num; i++) {
		uint32_t cur_size = MIN(block_size, total_size - verified);

		ret = readflash(i, flash_info.read_mode, g_readbuf);
		if (ret) {
			LOG_ERR("failed to read flash at block %d", i);
			return ret;
		}

		for (uint32_t j = 0; j < cur_size; j++) {
			if (g_readbuf[j] != g_writebuf[verified + j]) {
				uint32_t offset = verified + j;
				LOG_ERR("failed to verify at offset %x: read=%02x, write=%02x",
					offset, g_readbuf[j], g_writebuf[offset]);
				return -EIO;
			}
		}

		verified += cur_size;
		print_progress("Verifying", verified * 100 / total_size);
	}

	return 0;
}

static int enter_spi(void)
{
	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_LOW));
	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_OUTPUT));
	msleep(100);

	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_LOW));
	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_OUTPUT));
	msleep(100);

	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_HIGH));
	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_ALT));
	msleep(100);

	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_HIGH));
	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_ALT));

	return 0;
}

int init_dlb4_spi(void)
{
	CHECK_RET(start_d2ec(0x0b));

	CHECK_RET(get_dlb4_fw_version(soc.dlb4_fw_ver));

	CHECK_RET(enter_spi());

	return get_flash_id(soc.flash_id, 4);
}

int init_dlb4_i2c(void)
{
	uint8_t value;

	CHECK_RET(get_dlb4_fw_version(soc.dlb4_fw_ver));

	/* send special */
	CHECK_RET(start_d2ec(0x07));

	msleep(50);

	/* stop special */
	CHECK_RET(start_d2ec(0x0));
	/* enter debug mode */
	CHECK_RET(start_d2ec(0x03));

	value = 0x04;
	CHECK_RET(rw_dbgr_command_set(0x01, 0x1A, &value));
	CHECK_RET(rw_dbgr_command_set(0x00, 0x1A, &value));
	CHECK_RET(write_register(0x2006, 0x44));
	CHECK_RET(write_register(0x1063, 0x00));
	CHECK_RET(read_register(0x1080, &value));
	CHECK_RET(run_ctrl(0x81, 0, 0));

#if 0
	/* i2c init & enter debug mode(400K) */
	CHECK_RET(start_d2ec(0x02));
#endif

	/* i2c init & enter debug mode(1M) */
	CHECK_RET(start_d2ec(0x0C));
	/* set internal flash */
	CHECK_RET(start_d2ec(0x0A));

#if 0
	/* set external flash */
	CHECK_RET(start_d2ec(0x0B));
#endif

	CHECK_RET(get_chip_id(soc.chip_id));
	CHECK_RET(read_register(0x2085, &soc.chip_id[3]));
	CHECK_RET(read_register(0x2086, &soc.chip_id[4]));
	CHECK_RET(read_register(0x2087, &soc.chip_id[5]));

	CHECK_RET(get_flash_id(soc.flash_id, 0x04));

	CHECK_RET(update_non_sst_flash_sataus(0xff, 0, 0));

	CHECK_RET(write_register(0x1f05, 0x30));
	for (int i = 0; i < 0x20; i++) {
		CHECK_RET(write_register(0x2000 + 0xa0 + i, 0x00));
	}

	return 0;
}

int enable_qe_bit_and_reset_ec(void)
{
	/* enable qe bit after flashing */
	CHECK_RET(update_non_sst_flash_sataus(0x82, 0, 0x2));

	/* reset ec */
	CHECK_RET(write_register(0x2006, 0x44));

	CHECK_RET(run_ctrl(0x80, 0, 0));

	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_LOW));
	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_OUTPUT));

	sleep(1);

	CHECK_RET(dlb4_set_gpio(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_HIGH));

	return 0;
}

void show_itedlb4(const bool use_spi)
{
	LOG_RAW("ITE DLB4 FW Version : %02x%02x\n", soc.dlb4_fw_ver[0], soc.dlb4_fw_ver[1]);
	LOG_RAW("===================================\n");
	if (!use_spi) {
		LOG_RAW("CHIP ID          : %x%02x%02x ( %x%02x%02x )\n", soc.chip_id[0],
			soc.chip_id[1], soc.chip_id[2], soc.chip_id[3], soc.chip_id[4],
			soc.chip_id[5]);
	}
	LOG_RAW("Flash ID         : %02x %02x %02x\n", soc.flash_id[0], soc.flash_id[1],
		soc.flash_id[2]);
}

int init_usb_device(const uint16_t vid, const uint16_t pid)
{
	int ret;
	const struct libusb_version *version;
	struct libusb_device *dev;
	struct libusb_device_handle *handle;
	struct libusb_config_descriptor *config;
	const struct libusb_interface_descriptor *iface_desc;
	const struct libusb_endpoint_descriptor *ep_desc;
	struct libusb_device_descriptor desc;
	uint8_t in_ep = 0, out_ep = 0;

	version = libusb_get_version();
	LOG_INFO("using libusb v%d.%d.%d.%d", version->major, version->minor, version->micro,
		 version->nano);

	ret = libusb_init(NULL);
	if (ret) {
		LOG_ERR("failed to initialize usb");
		return ret;
	}

	LOG_INFO("open usb device (vid 0x%04x, pid 0x%04x)", vid, pid);
	handle = libusb_open_device_with_vid_pid(NULL, vid, pid);
	if (!handle) {
		LOG_ERR("please re-plug the download board or power on the EC");
		libusb_exit(NULL);
		return -EIO;
	}

	dev = libusb_get_device(handle);
	ret = libusb_get_device_descriptor(dev, &desc);
	if (ret < 0) {
		LOG_ERR("failed to get device descriptor");
		goto error;
	}

	ret = libusb_get_active_config_descriptor(dev, &config);
	if (ret < 0) {
		LOG_ERR("failed to get config descriptor");
		goto error;
	}

	for (int i = 0; i < config->bNumInterfaces; i++) {
		iface_desc = &config->interface[i].altsetting[0];

		for (int j = 0; j < iface_desc->bNumEndpoints; j++) {
			ep_desc = &iface_desc->endpoint[j];

			if ((ep_desc->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) ==
			    LIBUSB_TRANSFER_TYPE_BULK) {
				if (ep_desc->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
					in_ep = ep_desc->bEndpointAddress;
				} else {
					out_ep = ep_desc->bEndpointAddress;
				}
			}
		}
	}

	libusb_free_config_descriptor(config);

	if (!in_ep || !out_ep) {
		LOG_ERR("failed to find interrupt in/out endpoints");
		ret = -ENODEV;
		goto error;
	}

	soc_dlb4_info.handle = handle;
	soc_dlb4_info.in_ep = in_ep;
	soc_dlb4_info.out_ep = out_ep;

	LOG_INFO("found endpoints: in=0x%02x, out=0x%02x", in_ep, out_ep);
	return 0;

error:
	libusb_close(handle);
	libusb_exit(NULL);

	return ret;
}

void release_usb_device(void)
{
	LOG_INFO("release usb device...");
	if (!soc_dlb4_info.handle) {
		libusb_close(soc_dlb4_info.handle);
	}
	libusb_exit(NULL);
}

void free_write_read_buffer(void)
{
	SAFE_FREE_PTR(g_writebuf);
	SAFE_FREE_PTR(g_readbuf);
}

int init_file(char *filename)
{
	int ret;

	file.block_size = FILE_SIZE_64K;
	file.block_num = 16;
	file.flash_size = file.block_size * file.block_num;

	LOG_INFO("open file: %s", filename);
	file.fd = fopen(filename, "rb");
	if (!file.fd) {
		LOG_ERR("failed to open file: %s", filename);
		return -ENOENT;
	}

	/* get file size */
	if (fseek(file.fd, 0, SEEK_END) != 0) {
		LOG_ERR("failed to seek end of file");
		SAFE_CLOSE_FD(file.fd);
		return -EIO;
	}

	file.size = ftell(file.fd);
	if (file.size < 0) {
		LOG_ERR("failed to get file size");
		SAFE_CLOSE_FD(file.fd);
		return -EIO;
	}

	fseek(file.fd, 0, SEEK_SET);

	/* calculate blocks */
	file.block_num = file.size / file.block_size;
	if (file.size % file.block_size) {
		file.block_num++;
	}

	file.size_kb = file.size / 1024;
	if (file.size % 1024) {
		file.size_kb++;
	}

	file.flash_size = file.block_size * file.block_num;

	/* allocate write/read buffer */
	g_writebuf = malloc(file.flash_size);
	if (!g_writebuf) {
		LOG_ERR("failed to allocate writebuf");
		ret = -ENOMEM;
		goto out;
	}
	g_readbuf = malloc(file.flash_size);
	if (!g_readbuf) {
		LOG_ERR("failed to allocate readbuf");
		ret = -ENOMEM;
		goto out;
	}

	if (fread(g_writebuf, 1, file.flash_size, file.fd) != file.size) {
		ret = -EINVAL;
		goto out;
	}

	LOG_INFO("flash size: %d bytes, file size: %d bytes (%d KB)\n", file.flash_size, file.size,
		 file.size_kb);

	SAFE_CLOSE_FD(file.fd);
	return 0;

out:
	SAFE_CLOSE_FD(file.fd);
	free_write_read_buffer();

	return ret;
}

void interface_initialization(const bool use_spi)
{
	if (use_spi) {
		dbgr_code.op = OP_DBGR_SPI;
		dbgr_code.fun_code.flashid = DBGR_FUN_CODE_FLASHID_READ_SPI;
		dbgr_code.fun_code.read = DBGR_FUN_CODE_FLASH_READ_SPI;
		dbgr_code.fun_code.erase = DBGR_FUN_CODE_FLASH_ERASE_SPI;
		dbgr_code.fun_code.write = DBGR_FUN_CODE_FLASH_WRITE_SPI;

		flash_info.read_mode = 3;
		flash_info.erase_type = ITE_ERASE_TYPE_3_UNPROTECT_E;
		flash_info.erase_mode = MODE0_CHIP_ERASE;
		flash_info.write_type = ITE_PROGRAM_TYPE;
		flash_info.write_mode = ITE_PROGRAM_MODE;
	} else {
		dbgr_code.op = OP_DBGR_I2C;
		dbgr_code.fun_code.flashid = DBGR_FUN_CODE_FLASHID_READ_I2C;
		dbgr_code.fun_code.read = DBGR_FUN_CODE_FLASH_READ_I2C;
		dbgr_code.fun_code.erase = DBGR_FUN_CODE_FLASH_ERASE_I2C;
		dbgr_code.fun_code.write = DBGR_FUN_CODE_FLASH_WRITE_I2C;

		flash_info.read_mode = 3;
		flash_info.erase_type = ITE_ERASE_TYPE_3_UNPROTECT_E;
		flash_info.erase_mode = MODE1_SECTOR_ERASE;
		flash_info.write_type = ITE_PROGRAM_TYPE;
		flash_info.write_mode = ITE_PROGRAM_MODE;
	}
}
