#!/bin/sh

# Function to log and run a command
run_cmd() {
	echo "<info> command: $*"
	eval "$*"
}

# Install libusb 1.0.0
run_cmd "sudo apt-get install -y libusb-1.0-0-dev"

printf "\n"

# Add USB device udev rule
VID="048d"
PID="8390"
RULE_FILE="/etc/udev/rules.d/99-ite-download-board-usb-device.rules"

if [ -f "$RULE_FILE" ]; then
	echo "<info> udev rule file $RULE_FILE already exists"
else
	echo "<info> creating udev rule file $RULE_FILE..."
	run_cmd "sudo bash -c 'cat > \"$RULE_FILE\" <<EOF
# Allow access to USB device VID:$VID PID:$PID
SUBSYSTEM==\"usb\", ATTR{idVendor}==\"$VID\", ATTR{idProduct}==\"$PID\", MODE=\"0666\"
EOF'"

	# Reload udev rules
	echo "<info> reloading udev rules..."
	run_cmd "sudo udevadm control --reload-rules"
	run_cmd "sudo udevadm trigger"

	echo "<info> please unplug and re-plug the ite download board"
fi
