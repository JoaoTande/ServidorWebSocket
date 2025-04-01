# Compiler settings
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lssl -lcrypto -lpthread
TARGET = server
SRC = server.cpp

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(TARGET)

# Install dependencies (Ubuntu/Debian)
deps:
	sudo apt update
	sudo apt install -y g++ libssl-dev

# Run the server
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CXXFLAGS += -g
debug: $(TARGET)

.PHONY: all clean deps run debug
