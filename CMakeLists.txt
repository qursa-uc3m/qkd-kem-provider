if (WIN32)
    cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
else()
    cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
endif()

project(qkd-kem-provider LANGUAGES C)
set(OQSPROVIDER_VERSION_TEXT "0.1.0-dev")
set(CMAKE_C_STANDARD 11)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS ON)

# Set ETSI API version options
option(ETSI_004_API "Use ETSI 004 API" OFF)
option(ETSI_014_API "Use ETSI 014 API" ON)

# Make sure only one is enabled
if(ETSI_004_API AND ETSI_014_API)
    message(FATAL_ERROR "Only one ETSI API version can be enabled at a time")
endif()

if(ETSI_004_API)
    add_definitions(-DETSI_004_API)
    message(STATUS "Using ETSI 004 API")
elseif(ETSI_014_API)
    add_definitions(-DETSI_014_API)
    message(STATUS "Using ETSI 014 API")
else()
    # Default to 014 if none specified
    add_definitions(-DETSI_014_API)
    message(STATUS "Defaulting to ETSI 014 API")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Creating Debug build with OQS-Debug env vars enabled")
else()
    message(STATUS "Creating Release build")
    add_definitions( -DNDEBUG )
endif()

if(MSVC)
  set(CMAKE_EXE_LINKER_FLAGS 
      "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:LIBCMT")
  add_definitions(-DOQS_PROVIDER_NOATOMIC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  set(OQS_ADDL_SOCKET_LIBS ws2_32.lib gdi32.lib crypt32.lib)
else()
  add_compile_options(-Wunused-function)
  set(OQS_ADDL_SOCKET_LIBS "")
endif()

option(OQS_KEM_ENCODERS "Provide encoders (and decoders) for KEM algorithms " OFF)
if(${OQS_KEM_ENCODERS})
    message(STATUS "Build provides support for encoding KEMs")
    add_compile_definitions( OQS_KEM_ENCODERS )
endif()

option(QKD_KEY_ID_CH "Use channel-based key IDs" OFF)
if(QKD_KEY_ID_CH)
    add_compile_definitions(QKD_KEY_ID_CH)
    message(STATUS "Building with channel-based key IDs")
endif()

option(NOPUBKEY_IN_PRIVKEY "Do not include public keys in private key structures/PKCS#8 " OFF)
if(${NOPUBKEY_IN_PRIVKEY})
    message(STATUS "Build will not store public keys alongside private keys in PKCS#8 structures")
    add_compile_definitions( NOPUBKEY_IN_PRIVKEY )
else()
    message(STATUS "Build will store public keys in PKCS#8 structures")
endif()

option(OQS_PROVIDER_BUILD_STATIC "Build a static library instead of a shared library" OFF)
if(OQS_PROVIDER_BUILD_STATIC AND BUILD_SHARED_LIBS)
  message(FATAL_ERROR "`OQS_PROVIDER_BUILD_STATIC` is not compatible with `BUILD_SHARED_LIBS`.")
endif()

include(CheckLibraryExists)
include(CheckFunctionExists)

# Add required includes and install locations for openssl
find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
if (WIN32)
# get_filename_component seems to fail when facing windows paths
# so use new(er) cmake_path instruction there
cmake_path(GET OPENSSL_CRYPTO_LIBRARY PARENT_PATH OQS_MODULES_PARENT_PATH)
cmake_path(APPEND OQS_MODULES_PARENT_PATH "ossl-modules" OUTPUT_VARIABLE OPENSSL_MODULES_PATH)
else()
get_filename_component(OPENSSL_LIB_DIR ${OPENSSL_CRYPTO_LIBRARY} DIRECTORY)
set(OPENSSL_MODULES_PATH ${OPENSSL_LIB_DIR}/ossl-modules)
endif()

# Add required include for liboqs
find_package(liboqs REQUIRED)
get_target_property(LIBOQS_INCLUDE_DIR OQS::oqs INTERFACE_INCLUDE_DIRECTORIES)
get_target_property(LIBOQS_LIBRARY_TYPE OQS::oqs TYPE)
message(STATUS "liboqs found: Include dir at ${LIBOQS_INCLUDE_DIR} (${LIBOQS_LIBRARY_TYPE})")
include_directories(${LIBOQS_INCLUDE_DIR})

# Add required include for qkd-etsi-api
find_library(QKD_ETSI_API_LIB NAMES qkd-etsi-api-c-wrapper PATHS /usr/local/lib REQUIRED)
include_directories(/usr/local/include)
message(STATUS "QKD ETSI API found: ${QKD_ETSI_API_LIB}")

# Hints the compiler on the fact that the provider is being compiled into a static library.
function(targets_set_static_provider)
  foreach(target ${ARGN})
    target_compile_definitions(${target} PRIVATE "OQS_PROVIDER_STATIC")
    # Link UUID library to all targets
    target_link_libraries(${target} PRIVATE ${UUID_LIB} qkdkemprovider)
    if(NOT target STREQUAL qkdkemprovider)
      target_link_libraries(${target} PRIVATE qkdkemprovider)
    endif()
  endforeach()
endfunction()

# Provider module
add_subdirectory(oqsprov)

# Testing
include(CTest)
enable_testing()
add_subdirectory(test)

# Examples
add_subdirectory(examples)