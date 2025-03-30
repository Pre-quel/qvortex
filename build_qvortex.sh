#!/bin/bash
# Build script for Qvortex Hash Library
# This script compiles the C implementation into a shared library

set -e  # Exit on error

# Detect operating system
UNAME=$(uname)
if [ "$UNAME" == "Darwin" ]; then
    # macOS
    LIBEXT=".dylib"
    PLATFORM_FLAGS="-dynamiclib"
elif [ "$UNAME" == "Linux" ]; then
    # Linux
    LIBEXT=".so"
    PLATFORM_FLAGS="-shared"
else
    # Windows or other (assuming Windows/MinGW)
    LIBEXT=".dll"
    PLATFORM_FLAGS="-shared"
fi

# Source file
SRC="qvortex_lib.c"

# Output library
LIB_NAME="libqvortex$LIBEXT"

# Optimization level (-O3 for release, -O0 for debug)
OPT_LEVEL="-O3"

# Check if we should use debug build
if [ "$1" == "debug" ]; then
    OPT_LEVEL="-O0 -g"
    echo "Building in debug mode..."
fi

# Check for clang or fallback to gcc
if command -v clang &> /dev/null; then
    CC="clang"
    echo "Using clang compiler..."
else
    CC="gcc"
    echo "Using gcc compiler..."
fi

# Check for ARM platform for NEON support
if [[ "$UNAME" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
    # Apple Silicon (M1/M2)
    ARCH_FLAGS="-arch arm64"
    FEATURE_FLAGS="-DUSE_NEON=1"
    echo "Building for Apple Silicon with NEON support..."
elif [[ "$(uname -m)" =~ arm* ]] || [[ "$(uname -m)" =~ aarch64* ]]; then
    # Other ARM platforms
    ARCH_FLAGS="-march=native"
    FEATURE_FLAGS="-DUSE_NEON=1"
    echo "Building for ARM with NEON support..."
else
    # Intel/AMD platforms
    ARCH_FLAGS="-march=native"
    FEATURE_FLAGS="-DUSE_NEON=0"
    echo "Building for x86/x64 without NEON..."
fi

# Common compiler flags
COMMON_FLAGS="-Wall -Wextra $OPT_LEVEL $ARCH_FLAGS $FEATURE_FLAGS -fPIC"

# Link flags
LINK_FLAGS="-lm"  # Link with math library

echo "Compiling $SRC to $LIB_NAME..."
$CC $COMMON_FLAGS $PLATFORM_FLAGS -o $LIB_NAME $SRC $LINK_FLAGS

# Verify the library was created
if [ -f "$LIB_NAME" ]; then
    echo "Successfully built $LIB_NAME"
    
    # Optional: Build a test program
    if [ "$1" == "test" ] || [ "$2" == "test" ]; then
        echo "Building test program..."
        
        cat > test_qvortex.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "qvortex_lib.c"

int main(int argc, char *argv[]) {
    const char *test_data = argc > 1 ? argv[1] : "Hello, Qvortex!";
    size_t data_len = strlen(test_data);
    
    printf("Input: \"%s\" (%zu bytes)\n", test_data, data_len);
    
    // Allocate digest buffer
    uint8_t digest[32];
    
    // Test without key
    qvortex_hash((const uint8_t *)test_data, data_len, 0, 0, NULL, 0, digest);
    
    printf("Qvortex hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    
    // Test with key
    const char *key = "test key";
    qvortex_hash((const uint8_t *)test_data, data_len, 0, 0, 
                (const uint8_t *)key, strlen(key), digest);
    
    printf("Qvortex keyed hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    
    // Test incremental hashing
    qvortex_lite_ctx ctx;
    qvortex_init(&ctx, NULL, 0);
    
    // Split the input into two parts
    size_t half = data_len / 2;
    qvortex_update(&ctx, (const uint8_t *)test_data, half);
    qvortex_update(&ctx, (const uint8_t *)(test_data + half), data_len - half);
    qvortex_final(&ctx, digest);
    
    printf("Qvortex incremental hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    
    // Benchmark
    size_t bench_size = 1024 * 1024;  // 1 MB
    uint8_t *bench_data = malloc(bench_size);
    if (!bench_data) {
        printf("Memory allocation failed\n");
        return 1;
    }
    
    // Fill with pseudo-random data
    srand(time(NULL));
    for (size_t i = 0; i < bench_size; i++) {
        bench_data[i] = rand() & 0xFF;
    }
    
    clock_t start = clock();
    qvortex_hash(bench_data, bench_size, 0, 0, NULL, 0, digest);
    clock_t end = clock();
    
    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    double mb_per_sec = bench_size / (1024.0 * 1024.0) / seconds;
    
    printf("\nBenchmark: %.2f MB/s\n", mb_per_sec);
    
    free(bench_data);
    return 0;
}
EOF
        
        $CC $COMMON_FLAGS -o test_qvortex test_qvortex.c $LINK_FLAGS
        
        if [ -f "test_qvortex" ]; then
            echo "Successfully built test program. Running test..."
            ./test_qvortex
        else
            echo "Failed to build test program"
        fi
    fi
    
    # Optional: Create a simple Python test
    if [ "$1" == "python" ] || [ "$2" == "python" ]; then
        echo "Creating Python test..."
        
        cat > test_qvortex.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
import time
from qvortex import QvortexHash, hash

def main():
    # Test basic hashing
    test_data = sys.argv[1] if len(sys.argv) > 1 else "Hello, Qvortex!"
    print(f"Input: \"{test_data}\" ({len(test_data)} bytes)")
    
    try:
        # Create a Qvortex instance
        qvortex = QvortexHash()
        
        # Test without key
        digest1 = qvortex.hash(test_data)
        print(f"Qvortex hash: {digest1.hex()}")
        
        # Test with key
        key = "test key"
        digest2 = qvortex.hash(test_data, key)
        print(f"Qvortex keyed hash: {digest2.hex()}")
        
        # Test incremental hashing
        ctx = qvortex.new()
        # Split the input into two parts
        half = len(test_data) // 2
        ctx.update(test_data[:half])
        ctx.update(test_data[half:])
        digest3 = ctx.digest()
        print(f"Qvortex incremental hash: {digest3.hex()}")
        
        # Verify the incremental result matches the one-shot result
        print(f"Incremental matches one-shot: {digest1 == digest3}")
        
        # Test convenience function
        digest4 = hash(test_data)
        print(f"Convenience function hash: {digest4.hex()}")
        
        # Benchmark
        bench_size = 1024 * 1024  # 1 MB
        bench_data = os.urandom(bench_size)
        
        start_time = time.time()
        qvortex.hash(bench_data)
        end_time = time.time()
        
        seconds = end_time - start_time
        mb_per_sec = bench_size / (1024 * 1024) / seconds
        
        print(f"\nBenchmark: {mb_per_sec:.2f} MB/s")
        
        print(f"Qvortex version: {qvortex.version}")
        
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure the Qvortex library is properly installed.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF
        
        chmod +x test_qvortex.py
        
        echo "Python test created. Run with: ./test_qvortex.py"
    fi
    
else
    echo "Failed to build $LIB_NAME"
    exit 1
fi

echo "Done."