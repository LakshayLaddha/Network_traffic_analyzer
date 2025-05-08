# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -I./include
LDFLAGS = -lpcap -lpthread

# Source files and object files
SRC_DIR = src
OBJ_DIR = obj
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))

# Target executable
TARGET = network_analyzer

# Phony targets
.PHONY: all clean debug

# Default target
all: $(TARGET)

# Debug build with extra debug flags
debug: CFLAGS += -DDEBUG -g3 -O0
debug: clean $(TARGET)

# Create output directories
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files to create executable
$(TARGET): $(OBJ_FILES)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(TARGET)
	@echo "Clean complete"

# Install dependencies (for Debian-based systems)
install-deps:
	apt-get update
	apt-get install -y libpcap-dev build-essential
	@echo "Dependencies installed"

# Run the analyzer with default options
run: $(TARGET)
	sudo ./$(TARGET) -v

# Generate documentation
docs:
	mkdir -p docs
	doxygen Doxyfile

# Test rule for SYN flood detection
test-syn-flood: $(TARGET)
	sudo ./$(TARGET) -i lo -f "tcp" -v -v -v &
	sleep 2
	hping3 --syn -p 80 --flood -c 1000 127.0.0.1
	pkill -INT $(TARGET)

# Test rule for port scanning detection
test-port-scan: $(TARGET)
	sudo ./$(TARGET) -i lo -v -v -v &
	sleep 2
	nmap -T4 127.0.0.1
	pkill -INT $(TARGET)