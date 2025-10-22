# ===============================================
# Project: ITE Flasher
# ===============================================

# --- Directory Configuration ---
BUILD_DIR = build

# --- Build Configuration ---
CC       = gcc
CFLAGS   = -g -O2 -Wall
# Add the path to the libusb headers
INCLUDE  = -I/usr/include/libusb-1.0 -Iinclude

# --- Linker Configuration ---
TARGET   = ite-flasher
# Use explicit linker flag for library paths
LDFLAGS  = -L../lib
# Link with libusb-1.0
LDLIBS   = -lusb-1.0

# --- Source Files ---
SRCS     = ./src/ite_flasher.c
OBJS     = $(SRCS:.c=.o)

# --- Targets ---
.PHONY: all clean

# The 'all' target now depends on creating the build directory
all: $(TARGET)

# Rule to ensure the build directory exists
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# The executable depends on the object files AND the directory existing
$(TARGET): $(OBJS) | $(BUILD_DIR)
	# Link the object files and place the executable in the build folder
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDLIBS)
	# Automatically remove object files after successful linking
	$(RM) $^

%.o: %.c
	# Compile each source file (objects remain in the current folder)
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	# Remove object files (in case linking failed/was skipped) and the final executable
	$(RM) $(OBJS) $(BUILD_DIR)/$(TARGET)
	$(RM) -r $(BUILD_DIR)
