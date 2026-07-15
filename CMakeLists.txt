cmake_minimum_required(VERSION 3.16)

project(qkd-kem-provider VERSION 0.2.0 LANGUAGES C)

include(CTest)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(ETSI_004_API "Use the ETSI GS QKD 004 API" OFF)
option(ETSI_014_API "Use the ETSI GS QKD 014 API" ON)
option(QKD_KEY_ID_CH "Carry the QKD key identifier in the TLS key share" OFF)
set(QKD_BACKEND "simulated" CACHE STRING "QKD backend")
set(QKD_ETSI_API_SOURCE_DIR "" CACHE PATH
    "Optional qkd-etsi-api-c-wrapper source directory")

if((ETSI_004_API AND ETSI_014_API) OR
   (NOT ETSI_004_API AND NOT ETSI_014_API))
  message(FATAL_ERROR "Enable exactly one of ETSI_004_API or ETSI_014_API")
endif()
if(ETSI_004_API AND NOT QKD_KEY_ID_CH)
  message(FATAL_ERROR
    "ETSI 004 requires QKD_KEY_ID_CH=ON so both peers can join the stream before GET_KEY")
endif()

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)

if(NOT QKD_ETSI_API_SOURCE_DIR AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../qkd-etsi-api-c-wrapper/CMakeLists.txt")
  set(QKD_ETSI_API_SOURCE_DIR
      "${CMAKE_CURRENT_SOURCE_DIR}/../qkd-etsi-api-c-wrapper")
endif()

if(QKD_ETSI_API_SOURCE_DIR)
  set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(ENABLE_ETSI004 ${ETSI_004_API} CACHE BOOL "" FORCE)
  set(ENABLE_ETSI014 ${ETSI_014_API} CACHE BOOL "" FORCE)
  add_subdirectory("${QKD_ETSI_API_SOURCE_DIR}"
                   "${CMAKE_BINARY_DIR}/qkd-etsi-api" EXCLUDE_FROM_ALL)
  add_compile_definitions(QKDKEM_QKD_FLAT_HEADERS)

  if(TARGET qkd-etsi004-api-c-wrapper AND ETSI_004_API)
    set(QKD_ETSI_API_TARGET qkd-etsi004-api-c-wrapper)
  elseif(TARGET qkd-etsi014-api-c-wrapper AND ETSI_014_API)
    set(QKD_ETSI_API_TARGET qkd-etsi014-api-c-wrapper)
  elseif(TARGET qkd-etsi-api-c-wrapper)
    set(QKD_ETSI_API_TARGET qkd-etsi-api-c-wrapper)
  else()
    message(FATAL_ERROR "The selected QKD ETSI API target was not created")
  endif()
  target_compile_definitions(${QKD_ETSI_API_TARGET} PRIVATE
    _POSIX_C_SOURCE=200809L)
else()
  find_path(QKD_ETSI_API_INCLUDE_DIR
    NAMES qkd-etsi-api-c-wrapper/qkd_etsi_api.h REQUIRED)
  if(ETSI_004_API)
    set(_qkd_library_names qkd-etsi004-api-c-wrapper qkd-etsi-api-c-wrapper)
  else()
    set(_qkd_library_names qkd-etsi014-api-c-wrapper qkd-etsi-api-c-wrapper)
  endif()
  find_library(QKD_ETSI_API_LIBRARY NAMES ${_qkd_library_names} REQUIRED)
  add_library(qkd_etsi_api UNKNOWN IMPORTED)
  set_target_properties(qkd_etsi_api PROPERTIES
    IMPORTED_LOCATION "${QKD_ETSI_API_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${QKD_ETSI_API_INCLUDE_DIR}")
  set(QKD_ETSI_API_TARGET qkd_etsi_api)
endif()

add_library(qkdkemprovider MODULE
  qkdkem/algorithms.c
  qkdkem/kem.c
  qkdkem/keymgmt.c
  qkdkem/provider.c
  qkdkem/qkd.c)

target_include_directories(qkdkemprovider PRIVATE qkdkem)
target_compile_definitions(qkdkemprovider PRIVATE
  QKDKEM_VERSION="${PROJECT_VERSION}"
  $<$<BOOL:${ETSI_004_API}>:ETSI_004_API>
  $<$<BOOL:${ETSI_014_API}>:ETSI_014_API>
  $<$<BOOL:${QKD_KEY_ID_CH}>:QKD_KEY_ID_CH>)
target_compile_options(qkdkemprovider PRIVATE
  $<$<C_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion>)
target_link_libraries(qkdkemprovider PRIVATE
  OpenSSL::Crypto ${QKD_ETSI_API_TARGET})

set_target_properties(qkdkemprovider PROPERTIES
  PREFIX ""
  OUTPUT_NAME "qkdkemprovider"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

install(TARGETS qkdkemprovider
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/ossl-modules"
  RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/ossl-modules")

if(BUILD_TESTING)
  add_subdirectory(test)
endif()
