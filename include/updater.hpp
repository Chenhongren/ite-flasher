#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>

extern "C" {
#include <errno.h>
}

class Updater {
public:
    virtual ~Updater() = default;
    virtual int init() = 0;
    virtual int wait_for_chip_ready() { return 0; }
    virtual int erase() = 0;
    virtual int check() = 0;
    virtual int program() = 0;
    virtual int verify() = 0;
};

// Factory functions (optional, or use unique_ptr in main.cpp)
std::unique_ptr<Updater> createI2CUpdater();
std::unique_ptr<Updater> createSPIUpdater();
