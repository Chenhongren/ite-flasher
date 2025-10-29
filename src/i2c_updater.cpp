#include "updater.hpp"

extern "C" {
#include "ite_flasher.h"
#include <unistd.h>
}

#include <memory>
#include <iostream>

struct soc_info_t extern soc; // use the same soc from C

class I2CUpdaterImpl : public Updater {
public:
    int init() override {
        return init_dlb4_i2c();
    }

    int wait_for_chip_ready() override {
        int retries = 0;
        int ret;
        do {
            ret = init_dlb4_i2c();
            if (ret) return ret;
            if (soc.chip_id[0] != 0) break;
            fflush(stdout);
        // } while (retries++ < 100 && keep_running == 1);
        } while (retries++ < 100);

        if (soc.chip_id[0] == 0) return -ENXIO;
        return 0;
    }

    int erase() override { return flash_erase(false); } /* false = I2C */
    int check() override { return flash_check(); }
    int program() override { return flash_program(); }
    int verify() override { return flash_verify(); }
};

std::unique_ptr<Updater> createI2CUpdater() {
    return std::make_unique<I2CUpdaterImpl>();
}
