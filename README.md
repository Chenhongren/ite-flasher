# ITE EC Flasher Utility

A command-line utility for flashing, erasing, and verifying ITE Embedded Controller (EC) firmware.
Supports I2C and SPI(hasn't verified) interfaces and integrates optional stages for check and verify.

---

## Features

- Flash EC firmware from a binary image
- Erase flash memory only (`--erase` or `-e`)
- Skip `check` or `verify` stages when flashing
  - `--skip check` or `-s check`
  - `--skip verify` or `-s verify`
- Support SPI interface with `--usespi`(or `-u`)
- Dump EC register values using `--dump <offset> [len]` or `-p`
  - `len` is optional (defaults to 1)
  - Supports up to 256 registers at one time
- Optional debug mode output
- Display `ite-flasher` version and usage help

---

## Build

### Requirements
- GCC or Clang
- Make build system
- libusb (required, execute `requirement.sh`)
  ```bash
    ren@Ren-SurfacePro:~/itedlb4-linux-v106$ sudo sh requirement.sh
    [sudo] password for ren:
    <info> command: sudo apt-get install -y libusb-1.0-0-dev
    Reading package lists... Done
    Building dependency tree... Done
    Reading state information... Done
    libusb-1.0-0-dev is already the newest version (2:1.0.25-1ubuntu2).
    The following packages were automatically installed and are no longer required:
      apport-symptoms bc distro-info python3-automat python3-bcrypt python3-click python3-colorama python3-constantly python3-gdbm
      python3-hamcrest python3-hyperlink python3-incremental python3-problem-report python3-pycurl python3-service-identity python3-systemd
      python3-twisted python3-zope.interface
    Use 'sudo apt autoremove' to remove them.
    0 upgraded, 0 newly installed, 0 to remove and 161 not upgraded.

    <info> creating udev rule file /etc/udev/rules.d/99-ite-download-board-usb-device.rules...
    <info> command: sudo bash -c 'cat > "/etc/udev/rules.d/99-ite-download-board-usb-device.rules" <<EOF
    SUBSYSTEM=="usb", ATTR{idVendor}=="048d", ATTR{idProduct}=="8390", MODE="0666"
    EOF'
    <info> reloading udev rules...
    <info> command: sudo udevadm control --reload-rules
    <info> command: sudo udevadm trigger
    <info> please unplug and re-plug the ite download board
  ```
- Linux OS environment (Ubuntu 22.04.5 LTS (Jammy Jellyfish))

### Example
```bash
make clean; make all
```

---

## Usage

```bash
ren@Ren-SurfacePro:~/itedlb4-linux-v106$ sudo ./build/ite-flasher -h
ITE EC Flasher Utility v1.0.0
Usage: ./build/ite-flasher [options]

Options:
  -f, --filename <path>               Specify binary file to flash
  -s, --skip <check|verify>           Skip specified stage (check or verify)
  -u, --usespi                        Use SPI interface instead of default
  -e, --erase                         Erase flash only (no programming)
  -d, --debug_mode                    Enable debug messages
  -p, --dump_register <offset> [len]  Dump register(s) from device (max 256 bytes)
  -v, --version                       Show program version
  -h, --help                          Show this help message and exit

Examples:
  ./build/ite-flasher -f zephyr.bin -e
  ./build/ite-flasher -f zephyr.bin -s check
  ./build/ite-flasher -p 0x2085              # Dump one register
  ./build/ite-flasher -p 0x2085 0x10         # Dump 16 registers

```
