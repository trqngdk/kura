.PHONY: all setup-ramdisk dev build clean

# Configuration variables
TMP_DIR := ./tmp
RAMDISK_SIZE := 512m

all: dev

# Initialize volatile memory storage for upload streams (Linux target)
setup-ramdisk:
	@mkdir -p $(TMP_DIR)
	@sudo mount -t tmpfs -o size=$(RAMDISK_SIZE) tmpfs $(TMP_DIR)
	@echo "[+] RAM disk mounted on $(TMP_DIR) (Capacity: $(RAMDISK_SIZE))"

# Start the development server
dev:
	cargo run

# Compile the optimized release binary
build:
	cargo build --release

# Safely unmount volatile storage and wipe artifacts
clean:
	@sudo umount $(TMP_DIR) 2>/dev/null || true
	@rm -rf $(TMP_DIR)/*
	@cargo clean
	@echo "[+] Environment sanitized."