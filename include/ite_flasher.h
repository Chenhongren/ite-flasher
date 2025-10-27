/*
 * Copyright (c) 2025 ITE Technology Corporation.
 *
 * All Rights Reserved.
 */

#ifndef ITE_FLASHER_H_
#define ITE_FLASHER_H_

#define OUTPUT_LIBUSB_ERROR_STRING(err)                                                            \
	LOG_ERR("libusb: %s\n", libusb_strerror((enum libusb_error)err));

#define DLB4_CBW_SIGNATURE 0x43424c44
#define DLB4_CSW_SIGNATURE 0x53424c44
#define DLB4_CBW_CBLength  15

#define ITE_DIR_IN  0x00
#define ITE_DIR_OUT 0x01

#define ITE_ERASE_TYPE_3_UNPROTECT_E 0x03

#define ITE_PROGRAM_MODE 0x03
#define ITE_PROGRAM_TYPE 0x00

#define ITE_DLB_GPIO_C1     1
#define ITE_DLB_GPIO_C2     2
#define ITE_DLB_GPIO_H1     3
#define ITE_DLB_GPIO_H2     4
#define ITE_DLB_GPIO_G6     5 /* SPI Clock Pin */
#define ITE_DLB_GPIO_ALT    0
#define ITE_DLB_GPIO_OUTPUT 1
#define ITE_DLB_GPIO_HIGH   2
#define ITE_DLB_GPIO_LOW    3

#define FILE_SIZE_64K 0x10000

#define ITE_USB_VID 0x048D
#define ITE_USB_PID 0x8390

enum op_code_table {
	/* 0x0 and 0xEF are reserved */
	OP_FW_CTRL = 0xF0,
	/* 0xF1 is reserved */
	OP_DBGR_SPI = 0xF2,
	OP_DBGR_I2C = 0xF3,
};

enum ite_op_code_fw_ctrl_fun_code_table {
	/* 0x0 and 0x1 are reserved */
	FW_CTL_FUN_CODE_READ_FW_VER = 0x02,
	FW_CTL_FUN_CODE_SET_GPIO,
};

enum ite_op_code_dbgr_fun_code_table {
	DBGR_FUN_CODE_CHIPID_READ = 0,
	DBGR_FUN_CODE_FLASHID_READ_I2C,
	DBGR_FUN_CODE_FLASH_READ_I2C,
	DBGR_FUN_CODE_FLASH_ERASE_I2C,
	DBGR_FUN_CODE_FLASH_WRITE_I2C,
	DBGR_FUN_CODE_SET_PIN_DEFINE,
	/* 0x06 to 0x08 are reserved */
	DBGR_FUN_CODE_FLASH_R_SPI_STATUS = 0x09,
	/* 0x10 are reserved */
	DBGR_FUN_CODE_FLASHID_READ_SPI = 0x11,
	DBGR_FUN_CODE_FLASH_READ_SPI,
	DBGR_FUN_CODE_FLASH_ERASE_SPI,
	DBGR_FUN_CODE_FLASH_WRITE_SPI,
	/* 0x15 to 0x1F are reserved */
	DBGR_FUN_CODE_START_D2EC = 0x20,
	/* 0x21 and 0x22 are reserved */
	DBGR_FUN_CODE_WRITE_REG = 0x23,
	DBGR_FUN_CODE_READ_REG,
	/* 0x25 and 0x26 are reserved */
	DBGR_FUN_CODE_RUN_CTRL = 0x27,
	/* 0x28 to 0x2E are reserved */
	DBGR_FUN_CODE_DBGR_CMD_SET = 0x2F,
};

enum erase_mode {
	MODE0_CHIP_ERASE = 0,
	MODE1_SECTOR_ERASE,
	MODE2_BLOCK_ERASE,
};

struct dlb4_cbw_t {
	uint32_t dSignature;
	uint32_t dTag;
	uint32_t dDataLength;
	uint8_t bmFlags;
	uint8_t bCBLength;
	uint8_t CB[15];
};

struct dlb4_csw_t {
	uint32_t dSignature;
	uint32_t dTag;
	uint32_t dDataResidue;
	uint8_t bStatus;
};

struct soc_info_t {
	unsigned char dlb4_fw_ver[4];
	unsigned char chip_id[6];
	unsigned char flash_id[6];
};

struct flash_file_info_t {
	FILE *fd;
	int block_size;
	int block_num;
	int flash_size;
	int size_kb;
	int size;
};

struct flash_info_t {
	uint8_t readid_mode; /* read id command mode */
	uint8_t read_mode;   /* read command mode */
	uint8_t write_mode;  /* write command mode */
	uint8_t write_type;  /* write type */
	uint8_t erase_mode;  /* erase command mode */
	uint8_t erase_type;
};

struct soc_dlb4_info_t {
	uint8_t in_ep;
	uint8_t out_ep;
	libusb_device_handle *handle;
};

struct dlb4_operation_t {
	uint8_t op_code;
	uint8_t fun_code;
	uint8_t p1;
	uint8_t p2;
	uint8_t p3;
	uint8_t p4;
	uint8_t p5;
	uint8_t p6;
	uint8_t p7;
	uint8_t direction;
	uint8_t *buffer;
	uint32_t size;
};

struct dbgr_code_t {
	uint8_t op;

	struct {
		uint8_t flashid;
		uint8_t read;
		uint8_t erase;
		uint8_t write;
	} fun_code;
};

extern struct soc_info_t soc;

void interface_initialization(const bool use_spi);

int init_usb_device(uint16_t vid, uint16_t pid);
void release_usb_device(void);

int init_dlb4_spi(void);
int init_dlb4_i2c(void);
void show_itedlb4(const bool use_spi);

int init_file(char *filename);
void free_write_read_buffer(void);

int flash_erase(bool use_spi);
int flash_check(void);
int flash_program(void);
int flash_verify(void);

int enable_qe_bit_and_reset_ec(void);

int read_register(uint16_t offset, uint8_t *data);

#endif /* ITE_FLASHER_H_ */
