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

#include "libusb.h"
#include "ite_flasher.h"
#include "parameters.h"
#include "logging.h"

#define BIT(nr) (1UL << (nr))
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

/* TODO */
// #define VERSION "1.0.6.0.1"
#define ITE_FLASHER_VERSION "1.0.0"

#define ITE_USB_VID    0x048D
#define ITE_USB_PID    0x8390
#define ITE_USB_IN_EP  0x81
#define ITE_USB_OUT_EP 0x02

#define FILE_SIZE_64K 0x10000

static struct {
	unsigned char dlb4_fw_ver[4];
	unsigned char chip_id[6];
	unsigned char flash_id[6];
} soc;

struct {
	FILE *fd;
	int block_size;
	int block_num;
	int flash_size;
	int size_kb;
	int size;
} file;

unsigned char *g_readbuf;
unsigned char *g_writebuf;

volatile sig_atomic_t keep_running = 1;

static int perr(char const *format, ...)
{
	va_list args;
	int r;

	va_start(args, format);
	r = vfprintf(stderr, format, args);
	va_end(args);

	return r;
}

void hexdump(unsigned char *buffer, int offset, int len)
{
	for (int i = 0; i < len; i++) {
		if ((i % 16 == 0)) {
			LOG_RAW(" %06X :", offset + i);
		}
		LOG_RAW(" %02x", buffer[i]);
		if ((i % 16 == 7)) {
			LOG_RAW(" - ");
		}
		if (i % 16 == 15) {
			LOG_RAW("\n\r");
		}
	}
}

static int read_from_itedev(uint8_t *CMD, unsigned int ReadDataBytes, unsigned char *ReadData)
{
	int retry = 0;
	DLB4_CBW CBW;
	DLB4_CSW CSW;
	uint8_t szBuffer[32];
	int bytesWritten, bytesRead;
	int ret;

	do {
		int retries = 0;

		CBW.dSignature = DLB4_CBW_Signature;
		CBW.dTag = rand();
		CBW.dDataLength = ReadDataBytes;
		CBW.bmFlags = 0x80;
		CBW.bCBLength = DLB4_CBW_CBLength;
		memcpy(CBW.CB, CMD, CBW.bCBLength);
		memcpy(szBuffer, &CBW, sizeof(CBW));
		do {
			ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.out_ep,
						   (unsigned char *)&szBuffer, sizeof(CBW),
						   &bytesWritten, 1000);
			if (ret != LIBUSB_SUCCESS) {
				return ret;
			}

			if (ret == LIBUSB_ERROR_PIPE) {
				libusb_clear_halt(soc_dlb4_info.handle, soc_dlb4_info.out_ep);
			}
		} while ((ret == LIBUSB_ERROR_PIPE) && (retries++ < RETRY_MAX));

		if (bytesWritten != sizeof(CBW)) {
			return -1;
		}

		retries = 0;
		if (ReadDataBytes > 0) {
			bytesRead = 0;
			do {
				ret = libusb_bulk_transfer(soc_dlb4_info.handle,
							   soc_dlb4_info.in_ep, ReadData,
							   ReadDataBytes, &bytesRead, 5000);

				if (ret != LIBUSB_SUCCESS) {
					return ret;
				}
				if (ret == LIBUSB_ERROR_PIPE) {
					libusb_clear_halt(soc_dlb4_info.handle,
							  soc_dlb4_info.out_ep);
				}
			} while ((ret == LIBUSB_ERROR_PIPE) && (retries++ < RETRY_MAX));
		}

		retries = 0;
		do {
			ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.in_ep,
						   (unsigned char *)&szBuffer, sizeof(CSW),
						   &bytesRead, 1000);

			if (ret == LIBUSB_ERROR_PIPE) {
				libusb_clear_halt(soc_dlb4_info.handle, soc_dlb4_info.out_ep);
			}
		} while ((ret == LIBUSB_ERROR_PIPE) && (retries++ < RETRY_MAX));
		memcpy(&CSW, szBuffer, sizeof(CSW));

		if (CSW.dSignature != DLB4_CSW_Signature) {
			LOG_ERR("error signature(%08x)", CSW.dSignature);
		}

	} while ((ret == LIBUSB_ERROR_PIPE) && (retry++ < RETRY_MAX));

	return ret;
}

static int write_to_itedev(uint8_t *CMD, unsigned int WriteDataBytes, unsigned char *WriteData)
{
	int i;
	DLB4_CBW CBW;
	DLB4_CSW CSW;
	uint8_t szBuffer[32];
	int bytesWritten, bytesRead;
	int ret;

	do {
		CBW.dSignature = DLB4_CBW_Signature;
		CBW.dTag = rand();
		CBW.dDataLength = WriteDataBytes;
		CBW.bmFlags = 0x00;
		CBW.bCBLength = DLB4_CBW_CBLength;
		memcpy(CBW.CB, CMD, CBW.bCBLength);
		memcpy(szBuffer, &CBW, sizeof(CBW));
		do {
			ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.out_ep,
						   (unsigned char *)&szBuffer, sizeof(CBW),
						   &bytesWritten, 1000);
			if (ret != LIBUSB_SUCCESS) {
				return ret;
			}
			if (ret == LIBUSB_ERROR_PIPE) {
				libusb_clear_halt(soc_dlb4_info.handle, soc_dlb4_info.out_ep);
			}
			i++;
		} while ((ret == LIBUSB_ERROR_PIPE) && (i < RETRY_MAX));

		if (bytesWritten != sizeof(CBW)) {
			return -1;
		}

		if (WriteDataBytes > 0) {
			do {
				ret = libusb_bulk_transfer(soc_dlb4_info.handle,
							   soc_dlb4_info.out_ep, WriteData,
							   WriteDataBytes, &bytesWritten, 5000);
				if (ret != LIBUSB_SUCCESS) {
					return ret;
				}
				if (ret == LIBUSB_ERROR_PIPE) {
					libusb_clear_halt(soc_dlb4_info.handle,
							  soc_dlb4_info.out_ep);
				}
				i++;
			} while ((ret == LIBUSB_ERROR_PIPE) && (i < RETRY_MAX));
		}

		do {
			ret = libusb_bulk_transfer(soc_dlb4_info.handle, soc_dlb4_info.in_ep,
						   (unsigned char *)&szBuffer, sizeof(CSW),
						   &bytesRead, 1000);
			if (ret != LIBUSB_SUCCESS) {
				return ret;
			}
			if (ret == LIBUSB_ERROR_PIPE) {
				libusb_clear_halt(soc_dlb4_info.handle, soc_dlb4_info.out_ep);
			}
			i++;
		} while ((ret == LIBUSB_ERROR_PIPE) && (i < RETRY_MAX));

		memcpy(&CSW, szBuffer, sizeof(CSW));
		if (CSW.dSignature != DLB4_CSW_Signature) {
			LOG_ERR("error signature(%08x)", CSW.dSignature);
			hexdump(szBuffer, 0, 32);
			return -1;
		}
	} while ((ret == LIBUSB_ERROR_PIPE) && (i < RETRY_MAX));

	return ret;
}

int DoCMD(DLB4_OP *cmd)
{
	int status = 0;
	unsigned char cmdbuf[DLB4_CBW_CBLength];

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
		status = read_from_itedev(cmdbuf, cmd->size, cmd->buffer);
	}

	if (cmd->direction == ITE_DIR_OUT) {
		status = write_to_itedev(cmdbuf, cmd->size, cmd->buffer);
	}

	return status;
}

// pin      : 1 => C1
//            2 => C2
//            3 => H1
//            4 => H2
// pin_data : 0 => ALT
//            1 => OUTPUT
//            2 => HIGH
//            3 => LOW
int Dlb4SetGPIO(uint8_t pin, uint8_t pin_data)
{
	unsigned char data[2];

	data[0] = pin;
	data[1] = pin_data;

	cmdParam.op_code = ITE_FW_CTL;
	cmdParam.fun_code = 0x03;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = 4;

	return DoCMD(&cmdParam);
}

int GetDlb4FwVer(uint8_t *fwver)
{
	unsigned char data[4];
	int ret;

	cmdParam.op_code = ITE_FW_CTL;
	cmdParam.fun_code = ITE_FW_CTL_READ_FW_VER;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = 4;

	ret = DoCMD(&cmdParam);
	memcpy(fwver, data, 4);
	return ret;
}

int SetPinDef(void)
{
	unsigned char data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x09};

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_SetPinDef;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = 15;

	return DoCMD(&cmdParam);
}

int GetChipID(uint8_t *chipid)
{
	unsigned char data[3];
	int ret;

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_CHIPID_READ;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = 3;

	ret = DoCMD(&cmdParam);
	memcpy(chipid, data, 3);
	return ret;
}

int GetFlashID(uint8_t *flashid, uint8_t mode)
{
	unsigned char data[5];
	int ret;

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_FLASHID;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = 5;
	cmdParam.p1 = mode;

	ret = DoCMD(&cmdParam);
	memcpy(flashid, data, 5);
	return ret;
}

int StartD2ec(uint8_t mode)
{
	unsigned char data[1];

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_START_D2EC;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = 1;
	cmdParam.p1 = mode;

	return DoCMD(&cmdParam);
}

int RunCtrl(uint8_t p1, uint8_t p2, uint8_t p3)
{
	unsigned char data[1];

	data[0] = 0x24; // dummy test
	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_RUN_CTRL;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = 1;
	cmdParam.p1 = p1;
	cmdParam.p2 = p2;
	cmdParam.p3 = p3;

	return DoCMD(&cmdParam);
}

int RwDbgrCmdSet(uint8_t rw, uint8_t cmd, uint8_t *value)
{
	unsigned char data[1];
	int ret;

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_DBGR_CMD_SET;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = 1;
	cmdParam.p1 = rw;
	cmdParam.p2 = cmd;
	cmdParam.p3 = *value;

	ret = DoCMD(&cmdParam);
	if (rw == 0) {
		*value = data[0];
	}

	return ret;
}

int WriteReg(uint8_t high, uint8_t low, uint8_t data)
{
	unsigned char local[1];

	local[0] = data;

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_WRITE_REG;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = local;
	cmdParam.size = 1;
	cmdParam.p1 = high;
	cmdParam.p2 = low;
	cmdParam.p7 = 0xf0;

	return DoCMD(&cmdParam);
}

int ReadReg(uint8_t high, uint8_t low, uint8_t *data)
{
	unsigned char local[1];
	int ret;

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_READ_REG;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = local;
	cmdParam.size = 1;
	cmdParam.p1 = high;
	cmdParam.p2 = low;
	cmdParam.p7 = 0xf0;

	ret = DoCMD(&cmdParam);
	memcpy(data, local, 1);

	return ret;
}

int WriteNonSSTFlashStatus(uint8_t byte_count, uint8_t s1, uint8_t s2)
{

	unsigned char local[byte_count];
	int ret;

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_FLASH_R_SPI_STATUS;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = local;
	cmdParam.size = byte_count;
	cmdParam.p1 = byte_count;
	cmdParam.p2 = s1;
	cmdParam.p3 = s2;

	ret = DoCMD(&cmdParam);
	LOG_RAW("\n\rProtect Status: mode=%x data=%x %x\n\r", byte_count, local[0], local[1]);

	return ret;
}

int eraseflash(int block_num, uint8_t sector_num, uint8_t erase_mode, uint8_t erase_type)
{
	unsigned char local[1];

	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_ERASE;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = local;
	cmdParam.size = 1;
	cmdParam.p1 = erase_mode;
	cmdParam.p2 = erase_type;
	cmdParam.p3 = (block_num % 256);
	cmdParam.p4 = sector_num;
	cmdParam.p5 = (block_num / 256);
	cmdParam.p6 = 0; // switch rom

	return DoCMD(&cmdParam);
}

int readflash(int block_num, uint8_t command_mode, uint8_t *data)
{
	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_READ;
	cmdParam.direction = ITE_DIR_IN;
	cmdParam.buffer = data;
	cmdParam.size = FILE_SIZE_64K;
	cmdParam.p1 = block_num % 256;   // BA
	cmdParam.p2 = command_mode;      // read mode
	cmdParam.p3 = 0;                 // dummy
	cmdParam.p4 = 0;                 // dummy
	cmdParam.p5 = (block_num / 256); // EBA
	cmdParam.p6 = 0;                 // switch rom

	return DoCMD(&cmdParam);
}

int writeflash(int block_num, uint8_t command_mode, uint8_t program_type, uint8_t *data, int len)
{
	cmdParam.op_code = ITE_OP_CODE;
	cmdParam.fun_code = ITE_FUN_CODE_WRITE;
	cmdParam.direction = ITE_DIR_OUT;
	cmdParam.buffer = data;
	cmdParam.size = len;
	cmdParam.p1 = command_mode;
	cmdParam.p2 = block_num % 256;
	cmdParam.p3 = program_type;
	cmdParam.p5 = (block_num / 256); // EBA
	cmdParam.p6 = 0;                 // switch rom

	return DoCMD(&cmdParam);
}

int eraseall()
{
	int ret;

	if ((flags & BIT(FLAG_USE_SPI))) {
		// chip erase
		//  copy ini file set sector num as 4

		eraseflash(file.block_num, 4, Flash.erase_mode, Flash.erase_type);
		LOG_INFO("\rEraseing...      : 100%%\n\r");
		fflush(stdout);

	} else {
		// sector erase
		for (int i = 0; i < file.block_num; i++) {
			for (int j = 0; j < 0x10; j++) {
				ret = eraseflash(i, ((j << 4) + 0xF), Flash.erase_mode,
						 Flash.erase_type);
				if (ret < 0) {
					return ret;
				}
			}
			LOG_RAW("\rEraseing...      : %d%%", (i + 1) * 100 / (file.block_num));
			fflush(stdout);
		}
		LOG_RAW("\n\r");
	}
	return 0;
}

int programall()
{
	int ret;

	for (int i = 0; i < file.block_num; i++) {

		ret = writeflash(i, Flash.write_mode, Flash.write_type,
				 (unsigned char *)(g_writebuf + (i * FILE_SIZE_64K)),
				 FILE_SIZE_64K);
		LOG_RAW("\rProgramng...     : %d%%", (i + 1) * 100 / (file.block_num));
		fflush(stdout);
		if (ret < 0) {
			return ret;
		}
	}
	LOG_RAW("\n\r");
	return 0;
}

int checkall()
{
	for (int i = 0; i < file.block_num; i++) {
		int ret;

		ret = readflash(i, Flash.read_mode,
				(unsigned char *)(g_readbuf + i * FILE_SIZE_64K));
		if (ret < 0) {
			LOG_ERR("failed to read flash");
			return ret;
		}

		for (int j = 0; j < FILE_SIZE_64K; j++) {
			int offset = i * FILE_SIZE_64K + j;
			if (g_readbuf[offset] != 0xff) {
				LOG_ERR("failed to check: offset[%x]=%x not 0xff", offset,
					g_readbuf[offset]);
				hexdump(g_readbuf + offset, offset, 64);
				return -EINVAL;
			}
		}

		LOG_RAW("\rChecking...      : %d%%", (i + 1) * 100 / (file.block_num));
		fflush(stdout);
	}

	LOG_RAW("\n\r");
	return 0;
}

int verifyall()
{
	int ret;

	for (int i = 0; i < file.block_num; i++) {
		ret = readflash(i, Flash.read_mode,
				(unsigned char *)(g_readbuf + i * FILE_SIZE_64K));
		if (ret < 0) {
			return ret;
		}
		for (int j = 0; j < FILE_SIZE_64K; j++) {
			int l = i * FILE_SIZE_64K + j;
			if (g_readbuf[l] != g_writebuf[l]) {
				LOG_ERR("\n\rfailed to verify at offset r[%x]=%x w[%x]=%x", l,
					g_readbuf[l], l, g_writebuf[l]);
				return 1;
			}
		}
		LOG_RAW("\rVerifying...     : %d%%", (i + 1) * 100 / (file.block_num));
		fflush(stdout);
	}

	LOG_RAW("\n\r");

	return 0;
}

int enter_spi(void)
{
	Dlb4SetGPIO(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_LOW);
	Dlb4SetGPIO(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_OUTPUT);
	msleep(100);

	Dlb4SetGPIO(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_LOW);
	Dlb4SetGPIO(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_OUTPUT);
	msleep(100);

	Dlb4SetGPIO(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_HIGH);
	Dlb4SetGPIO(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_ALT);
	msleep(100);

	Dlb4SetGPIO(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_HIGH);
	Dlb4SetGPIO(ITE_DLB_GPIO_G6, ITE_DLB_GPIO_ALT);

	return 0;
}

int init_dlb4_spi(void)
{
	ITE_OP_CODE = ITE_OP_CODE_DBGR_X;

	CALL_CHECK(StartD2ec(0x0b));
	CALL_CHECK(GetDlb4FwVer(soc.dlb4_fw_ver));
	enter_spi();
	CALL_CHECK(GetFlashID(soc.flash_id, 4));

	return 0;
}

int init_dlb4()
{
	uint8_t value;

	ITE_OP_CODE = ITE_OP_CODE_DBGR_O;

	Flash.read_mode = 3;
	Flash.erase_type = ITE_ERASE_TYPE_3_UNPROTECT_E;
	Flash.erase_mode = ITE_ERASE_MODE_1_SECTOR_ERASE;
	Flash.write_type = 0; // ITE_PROGRAM_TYPE
	Flash.write_mode = 3; // ITE_PROGRAM_MODE

	CALL_CHECK(GetDlb4FwVer(soc.dlb4_fw_ver));
	CALL_CHECK(StartD2ec(7)); // Send Special
	msleep(50);
	CALL_CHECK(StartD2ec(0)); // Stop Special
	CALL_CHECK(StartD2ec(3)); // Enter Debug Mode

	value = 0x04;
	RwDbgrCmdSet(0x01, 0x1A, &value);
	RwDbgrCmdSet(0x00, 0x1A, &value);

	CALL_CHECK(WriteReg(0x20, 0x06, 0x44));
	CALL_CHECK(WriteReg(0x10, 0x63, 0x00));
	CALL_CHECK(ReadReg(0x10, 0x80, &value));

	CALL_CHECK(RunCtrl(0x81, 0, 0));
	// CALL_CHECK(StartD2ec(0x02)); //I2C Init & Enter Debug Mode //400K
	CALL_CHECK(StartD2ec(12));   // I2C Init & Enter Debug Mode //1M
	CALL_CHECK(StartD2ec(0x0a)); // Set Internal Flash
	// CALL_CHECK(StartD2ec(11)); //Set External Flash
	CALL_CHECK(GetChipID(soc.chip_id));
	ReadReg(0x20, 0x85, &soc.chip_id[3]);
	ReadReg(0x20, 0x86, &soc.chip_id[4]);
	ReadReg(0x20, 0x87, &soc.chip_id[5]);
	CALL_CHECK(GetFlashID(soc.flash_id, 0x04));
	// CALL_CHECK(WriteNonSSTFlashStatus(0x82,0,0x2));
	CALL_CHECK(WriteNonSSTFlashStatus(0xff, 0, 0));

	// 20220223 un-protect flash
	CALL_CHECK(WriteReg(0x1f, 0x05, 0x30));
	for (int i = 0; i < 0x20; i++) {
		CALL_CHECK(WriteReg(0x20, 0xa0 + i, 0x00));
	}

	return 0;
}

int reset_ec(void)
{
	CALL_CHECK(WriteReg(0x20, 0x06, 0x44));
	CALL_CHECK(RunCtrl(0x80, 0, 0));

	Dlb4SetGPIO(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_LOW);
	Dlb4SetGPIO(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_OUTPUT);

	sleep(1);

	Dlb4SetGPIO(ITE_DLB_GPIO_C1, ITE_DLB_GPIO_HIGH);

	return 0;
}

void show_itedlb4(void)
{
	LOG_RAW("ITE DLB4 FW Version : %02x%02x\n", soc.dlb4_fw_ver[0], soc.dlb4_fw_ver[1]);
	LOG_RAW("===================================\n");
	if (!(flags & BIT(FLAG_USE_SPI))) {
		LOG_RAW("CHIP ID          : %x%02x%02x ( %x%02x%02x )\n", soc.chip_id[0],
			soc.chip_id[1], soc.chip_id[2], soc.chip_id[3], soc.chip_id[4],
			soc.chip_id[5]);
	}
	LOG_RAW("Flash ID         : %02x %02x %02x\n", soc.flash_id[0], soc.flash_id[1],
		soc.flash_id[2]);
}

int init_usb_device(const uint16_t vid, const uint16_t pid, const uint8_t in_ep,
		    const uint8_t out_ep)
{
	int ret;
	const struct libusb_version *version;

	version = libusb_get_version();
	LOG_INFO("using libusb v%d.%d.%d.%d", version->major, version->minor, version->micro,
		 version->nano);

	ret = libusb_init(NULL);
	if (ret) {
		LOG_ERR("failed to initialize usb\n\r");
		return ret;
	}

	LOG_INFO("open usb device(vid 0x%x, pid 0x%x)", vid, pid);
	soc_dlb4_info.handle = libusb_open_device_with_vid_pid(NULL, vid, pid);
	if (!soc_dlb4_info.handle) {
		LOG_ERR("please re-plug the download board or power on the ec");
		ret = -EIO;
	}
	soc_dlb4_info.in_ep = in_ep;
	soc_dlb4_info.out_ep = out_ep;

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

void exit_file(void)
{
	SAFE_FREE_PTR(g_writebuf);
	SAFE_FREE_PTR(g_readbuf);
	SAFE_CLOSE_FD(file.fd);
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
		goto error;
	}
	g_readbuf = malloc(file.flash_size);
	if (!g_readbuf) {
		LOG_ERR("failed to allocate readbuf");
		ret = -ENOMEM;
		goto error;
	}

	if (fread(g_writebuf, 1, file.flash_size, file.fd) != file.size) {
		ret = -EINVAL;
		goto error;
	}

	LOG_INFO("flash size: %d bytes, file size: %d bytes (%d KB)\n", file.flash_size, file.size,
		 file.size_kb);

	return 0;

error:
	exit_file();

	return ret;
}

void show_time(void)
{
	time_t now = time(NULL);
	char *time_str = ctime(&now);

	/* remove the trailing newline */
	time_str[strlen(time_str) - 1] = '\0';

	LOG_INFO("current time: %s", time_str);
}

void print_parameters(void)
{
	char intfs[8];

	LOG_INFO("-------------------------------");
	if (flags & BIT(FLAG_USE_SPI)) {
		snprintf(intfs, sizeof(intfs), "spi");
	} else {
		snprintf(intfs, sizeof(intfs), "i2c");
	}
	LOG_INFO("update firmware via %s interface", intfs);

	if (flags & BIT(FLAG_DEBUG_MODE_ENABLE)) {
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
		LOG_INFO("skip %sstage(s)", skip_stages);
	}

out:
	LOG_INFO("-------------------------------\n");
}

void interface_initialization(void)
{
	if ((flags & BIT(FLAG_USE_SPI))) {
		ITE_CONNECT_MODE = ITE_CONNECT_MODE_NODBGR;
		ITE_OP_CODE = ITE_OP_CODE_DBGR_X;
		ITE_FUN_CODE_FLASHID = ITE_FUN_CODE_FLASHID_READ_SPI;
		ITE_FUN_CODE_READ = ITE_FUN_CODE_FLASH_READ_SPI;
		ITE_FUN_CODE_ERASE = ITE_FUN_CODE_FLASH_ERASE_SPI;
		ITE_FUN_CODE_WRITE = ITE_FUN_CODE_FLASH_WRITE_SPI;

		Flash.read_mode = 3;
		Flash.erase_type = ITE_ERASE_TYPE_3_UNPROTECT_E;
		Flash.erase_mode = ITE_ERASE_MODE_0_CHIP_ERASE;
		Flash.write_type = 0; // ITE_PROGRAM_TYPE
		Flash.write_mode = 3; // ITE_PROGRAM_MODE
	} else {
		ITE_CONNECT_MODE = ITE_CONNECT_MODE_DBGR;
		ITE_OP_CODE = ITE_OP_CODE_DBGR_O;
		ITE_FUN_CODE_FLASHID = ITE_FUN_CODE_FLASHID_READ;
		ITE_FUN_CODE_READ = ITE_FUN_CODE_FLASH_READ;
		ITE_FUN_CODE_ERASE = ITE_FUN_CODE_FLASH_ERASE;
		ITE_FUN_CODE_WRITE = ITE_FUN_CODE_FLASH_WRITE;

		Flash.read_mode = 3;
		Flash.erase_type = ITE_ERASE_TYPE_3_UNPROTECT_E;
		Flash.erase_mode = ITE_ERASE_MODE_1_SECTOR_ERASE;
		Flash.write_type = 0; // ITE_PROGRAM_TYPE
		Flash.write_mode = 3; // ITE_PROGRAM_MODE
	}
}

void signal_handler(int signum)
{
	if (signum == SIGINT) {
		LOG_WARN("ite-flasher exits after completing this stage...");
		keep_running = 0;
	}
}

void print_help(const char *progname)
{
	LOG_RAW("ITE EC Flasher Utility v%s\n", ITE_FLASHER_VERSION);
	LOG_RAW("Usage: %s [options]\n\n", progname);
	LOG_RAW("Options:\n");
	LOG_RAW("  -f, --filename <path>        Specify binary file to flash\n");
	LOG_RAW("  -s, --skip <check|verify>    Skip specified stage (check or verify)\n");
	LOG_RAW("  -u, --usespi                 Use SPI interface instead of default\n");
	LOG_RAW("  -e, --erase                  Erase flash only (no programming)\n");
	LOG_RAW("  -d, --debug_mode             Enable debug messages\n");
	LOG_RAW("  -v, --version                Show program version\n");
	LOG_RAW("  -h, --help                   Show this help message and exit\n\n");
	LOG_RAW("Examples:\n");
	LOG_RAW("  %s -f zephyr.bin -e\n", progname);
	LOG_RAW("  %s -f fw.bin -s check\n", progname);
	LOG_RAW("  %s -f fw.bin -u -s verify\n\n", progname);
}

int main(int argc, char **argv)
{
	int ret = 0;
	int option_index = 0;
	int c;
	char *filename = NULL;
	char *optstring = "f:s:uedvh";
	const struct option long_options[] = {
		{"filename", required_argument, NULL, 'f'}, {"skip", required_argument, NULL, 's'},
		{"usespi", no_argument, NULL, 'u'},         {"erase", no_argument, NULL, 'e'},
		{"debug_mode", no_argument, NULL, 'd'},     {"version", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},           {0, 0, 0, 0}};

	while (1) {
		c = getopt_long(argc, argv, optstring, long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'd':
			flags |= BIT(FLAG_DEBUG_MODE_ENABLE);
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

	print_parameters();

	interface_initialization();

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

	ret = init_usb_device(ITE_USB_VID, ITE_USB_PID, ITE_USB_IN_EP, ITE_USB_OUT_EP);
	if (ret < 0) {
		goto out;
	}

	/* init */
	if ((flags & BIT(FLAG_USE_SPI))) {
		ret = init_dlb4_spi();
	} else {
		int loop = 0;

		do {
			ret = init_dlb4();

			if (ret) {
				goto out;
			}

			if (soc.chip_id[0] != 0) {
				break;
			}

			fflush(stdout);
		} while (loop++ < 2000 && keep_running == 1);

		if (soc.chip_id[0] == 0) {
			LOG_ERR("\n\rfailed to get chip id. please re-run the program");
			ret = -ENXIO;
			goto out;
		}
	}

	show_itedlb4();

	/* erase stage */
	if (file.size <= FILE_SIZE_64K) {
		for (int i = 0; i < file.size_kb; i++) {
			int blk_no = 0;
			int sec_no = 0;

			blk_no = ((i << 4) & 0xFF00) >> 8;
			sec_no = (i << 4) & 0xF0;
			eraseflash(blk_no, sec_no + 0xf, Flash.erase_mode, Flash.erase_type);
			LOG_RAW("\rEraseing...      : %d%%", (i + 1) * 100 / (file.size_kb));
			fflush(stdout);
		}
	} else {
		CALL_CHECK(eraseall());
	}

	if (flags & BIT(FLAG_ERASE_STAGE_ONLY) || !keep_running) {
		ret = 0;
		goto out;
	}

	/* check stage */
	if (file.size > FILE_SIZE_64K) {
		if (!(flags & BIT(FLAG_SKIP_CHECK_STAGE))) {
			CALL_CHECK(checkall());
		}
	}

	if (!keep_running) {
		ret = 0;
		goto out;
	}

	/* program stage */
	if (file.size <= FILE_SIZE_64K) {
		writeflash(0, Flash.write_mode, Flash.write_type,
			   (unsigned char *)(g_writebuf + (0 * 4096)), file.size);
		LOG_RAW("\n\rProgramng...     : 100%%\n\r");
		fflush(stdout);
	} else {
		CALL_CHECK(programall());
	}

	if (!keep_running) {
		ret = 0;
		goto out;
	}

	/* verify stage */
	if (file.size <= FILE_SIZE_64K) {
		readflash(0, Flash.read_mode, (unsigned char *)(g_readbuf + 0 * 4096));
		for (int i = 0; i < file.size; i++) {
			if (g_readbuf[i] != g_writebuf[i]) {
				LOG_ERR("failed to verify at offset r[%x]=%x w[%x]=%x", i,
					g_readbuf[i], i, g_writebuf[i]);
				ret = -EINVAL;
				goto out;
			}
			LOG_RAW("\rVerifying...     : %d%%", (i + 1) * 100 / (file.size));
			fflush(stdout);
		}
		LOG_RAW("\n\r");
	} else {
		if (!(flags & BIT(FLAG_SKIP_VERIFY_STAGE))) {
			CALL_CHECK(verifyall());
		}
	}

	if (!keep_running) {
		ret = 0;
		goto out;
	}

	// Enable QE Bit After flash
	CALL_CHECK(WriteNonSSTFlashStatus(0x82, 0, 0x2));

	reset_ec();

out:
	release_usb_device();
	exit_file();
	show_time();

	return ret;
}
