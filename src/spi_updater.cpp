
#include <memory>
#include <iostream>

#include "updater.hpp"

extern "C" {
#include "ite_flasher.h"
}

class SPIUpdaterImpl : public Updater {
public:
	int init() override { return init_dlb4_spi(); }
	int erase() override { return flash_erase(true); } /* true = SPI */
	int check() override { return flash_check(); }
	int program() override { return flash_program(); }
	int verify() override { return flash_verify(); }
};

std::unique_ptr<Updater> createSPIUpdater() {
	return std::make_unique<SPIUpdaterImpl>();
}
