# Compiler settings
CC = gcc
# Added include paths and SQLite linking flag
CFLAGS = -Wall -Wextra -O2 -Isrc
LDFLAGS = -lsqlite3 -lpthread

# Directories
SRCDIR = src
BUILDDIR = build

# Final executable name
TARGET = $(BUILDDIR)/defense_engine

# Find all .c files in src/ and its subdirectories
SOURCES := $(shell find $(SRCDIR) -name '*.c')
# Map them to the build directory while keeping the subdirectory structure
OBJECTS := $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SOURCES))

# Phony targets
.PHONY: all clean

# Default target
all: $(TARGET)

# Link object files to create the executable
$(TARGET): $(OBJECTS)
	@echo "Linking $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build successful! Run with: sudo ./$(TARGET)"

# Compile C files into object files and create subdirectories as needed
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up compiled files
clean:
	@echo "Cleaning up build directory..."
	rm -rf $(BUILDDIR)/*