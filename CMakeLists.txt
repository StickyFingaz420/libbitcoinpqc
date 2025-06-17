cmake_minimum_required(VERSION 3.10)
project(libbitcoinpqc C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set version
set(BITCOINPQC_VERSION_MAJOR 0)
set(BITCOINPQC_VERSION_MINOR 1)
set(BITCOINPQC_VERSION_PATCH 0)

# Library output settings
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Platform-specific settings
if(APPLE)
    # Set strict floating-point model for macOS to match other platforms
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffp-contract=off -fno-fast-math")
    # Define FPEMU macro for Falcon to use emulated floating-point on macOS
    # This avoids platform-specific floating-point behavior
    add_definitions(-DFALCON_FPEMU=1)
    message(STATUS "macOS detected: Using emulated floating-point for Falcon")
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/dilithium/ref
    ${CMAKE_CURRENT_SOURCE_DIR}/sphincsplus/ref
    ${CMAKE_CURRENT_SOURCE_DIR}/falcon
)

# Custom randombytes implementation
set(CUSTOM_RANDOMBYTES
    dilithium/ref/randombytes.c
    sphincsplus/ref/randombytes_custom.c
)

# ML-DSA-44 (Dilithium) source files
set(ML_DSA_SOURCES
    dilithium/ref/sign.c
    dilithium/ref/packing.c
    dilithium/ref/polyvec.c
    dilithium/ref/poly.c
    dilithium/ref/ntt.c
    dilithium/ref/reduce.c
    dilithium/ref/rounding.c
    dilithium/ref/fips202.c
    dilithium/ref/symmetric-shake.c
)

# SLH-DSA-Shake-128s (SPHINCS+) source files
set(SLH_DSA_SOURCES
    sphincsplus/ref/address.c
    sphincsplus/ref/fors.c
    sphincsplus/ref/hash_shake.c
    sphincsplus/ref/merkle.c
    sphincsplus/ref/sign.c
    sphincsplus/ref/thash_shake_simple.c
    sphincsplus/ref/utils.c
    sphincsplus/ref/utilsx1.c
    sphincsplus/ref/wots.c
    sphincsplus/ref/wotsx1.c
    sphincsplus/ref/fips202.c
)

# FN-DSA-512 (FALCON) source files
set(FN_DSA_SOURCES
    falcon/codec.c
    falcon/common.c
    falcon/falcon.c
    falcon/fft.c
    falcon/fpr.c
    falcon/keygen.c
    falcon/shake.c
    falcon/sign.c
    falcon/vrfy.c
    falcon/rng.c
)

# libbitcoinpqc source files
set(BITCOINPQC_SOURCES
    src/bitcoinpqc.c
    src/ml_dsa/utils.c
    src/ml_dsa/keygen.c
    src/ml_dsa/sign.c
    src/ml_dsa/verify.c
    src/slh_dsa/utils.c
    src/slh_dsa/keygen.c
    src/slh_dsa/sign.c
    src/slh_dsa/verify.c
    src/fn_dsa/utils.c
    src/fn_dsa/keygen.c
    src/fn_dsa/sign.c
    src/fn_dsa/verify.c
)

# Define the main library target
add_library(bitcoinpqc STATIC
    ${BITCOINPQC_SOURCES}
    ${ML_DSA_SOURCES}
    ${SLH_DSA_SOURCES}
    ${FN_DSA_SOURCES}
    ${CUSTOM_RANDOMBYTES}
)

# Set include directories for the library
target_include_directories(bitcoinpqc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set compile definitions for the library
target_compile_definitions(bitcoinpqc PRIVATE
    DILITHIUM_MODE=2  # ML-DSA-44 (Dilithium2)
    PARAMS=sphincs-shake-128s
    FALCON_LOGN_512=9
    CUSTOM_RANDOMBYTES=1
)

# Configure install paths
install(TARGETS bitcoinpqc
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
