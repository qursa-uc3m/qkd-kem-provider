include(GNUInstallDirs)
execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_definitions(-DOQSPROVIDER_VERSION_TEXT="${OQSPROVIDER_VERSION_TEXT}")
message(STATUS "Building commit ${GIT_COMMIT_HASH} in ${CMAKE_SOURCE_DIR}")
add_definitions(-DOQS_PROVIDER_COMMIT=" \(${GIT_COMMIT_HASH}\)")
set(PROVIDER_SOURCE_FILES
  oqsprov.c oqsprov_capabilities.c oqsprov_keys.c
  oqs_kmgmt.c oqs_kem.c
  oqs_encode_key2any.c oqs_endecoder_common.c oqs_decode_der2key.c oqsprov_bio.c
  oqs_qkd_ctx.c
  oqs_qkd_etsi_api_wrapper.c
  oqsprov.def
)
set(PROVIDER_HEADER_FILES
  oqs_prov.h oqs_qkd_kem.h oqs_qkd_ctx.h oqs_qkd_etsi_api_wrapper.h oqs_endecoder_local.h
)

set(OQS_LIBRARY_TYPE MODULE)
if(OQS_PROVIDER_BUILD_STATIC)
  set(OQS_LIBRARY_TYPE STATIC)
endif()

# Add UUID library
find_library(UUID_LIB uuid)
if(NOT UUID_LIB)
    message(FATAL_ERROR "libuuid not found. Please install uuid-dev package.")
endif()
message(STATUS "Found UUID library: ${UUID_LIB}")

add_library(qkdkemprovider ${OQS_LIBRARY_TYPE} ${PROVIDER_SOURCE_FILES})

# Pick up definition from parent scope
if(QKD_USE_qukaydee)
    add_compile_definitions(QKD_USE_QUKAYDEE)
elseif(QKD_USE_cerberis_xgr)
    add_compile_definitions(QKD_USE_CERBERIS_XGR)
elseif(QKD_USE_simulated)
    add_compile_definitions(QKD_USE_SIMULATED)
endif()

set_target_properties(qkdkemprovider
    PROPERTIES
    OUTPUT_NAME "qkdkemprovider"
    PUBLIC_HEADER "oqs_prov.h"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    VERSION ${OQSPROVIDER_VERSION_TEXT}
    SOVERSION 1
    # Compatibility version (-compatibility_version) and current version
    # (-current_version) are not compatible with a `MODULE` library.
    # However, `VERSION` and `SOVERSION` set these two flags.
    # The following two flags remove them.
    MACHO_COMPATIBILITY_VERSION OFF
    MACHO_CURRENT_VERSION OFF
    # For Windows DLLs
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if (OQS_LIBRARY_TYPE STREQUAL "MODULE")
  # When openssl looks for provider modules it does not prepend "lib" to the
  # provider name.
  set_target_properties(qkdkemprovider
    PROPERTIES
    PREFIX ""
  )

  if (APPLE)
    # OpenSSL looks for `.dylib` files on XNU-based platforms.
    # Because `MODULE` writes to a `.so` file by default, we must explicitely
    # set the suffix here.
    set_target_properties(qkdkemprovider
      PROPERTIES
      SUFFIX ".dylib"
    )
  endif()

  if (CYGWIN OR MSVC)
    # OpenSSL looks for `.dll` files on Windows platforms.
    # Because `MODULE` writes to a `.so` file by default, we must explicitely
    # set the suffix here.
    set_target_properties(qkdkemprovider
      PROPERTIES
      SUFFIX ".dll"
    )
  endif()
endif()

#target_link_libraries(qkdkemprovider PUBLIC OQS::oqs ${OPENSSL_CRYPTO_LIBRARY} ${OQS_ADDL_SOCKET_LIBS})

target_compile_definitions(qkdkemprovider 
    PUBLIC
    $<$<STREQUAL:${QKD_BACKEND},qukaydee>:QKD_USE_QUKAYDEE>
    $<$<STREQUAL:${QKD_BACKEND},cerberis_xgr>:QKD_USE_CERBERIS_XGR>
    $<$<STREQUAL:${QKD_BACKEND},simulated>:QKD_USE_SIMULATED>
)

target_link_libraries(qkdkemprovider
    PUBLIC
    ${UUID_LIB} 
    OQS::oqs 
    ${OPENSSL_CRYPTO_LIBRARY} 
    ${QKD_ETSI_API_LIB}
    ${OQS_ADDL_SOCKET_LIBS}
)

install(TARGETS qkdkemprovider
        LIBRARY DESTINATION "${OPENSSL_MODULES_PATH}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/oqs-provider/"
        RUNTIME DESTINATION "${OPENSSL_MODULES_PATH}")

if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE arm64)
elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE amd64)
endif()

install(TARGETS qkdkemprovider
        CONFIGURATIONS DebPack
        DESTINATION .
        LIBRARY DESTINATION lib/ossl-modules
        ARCHIVE DESTINATION lib/
        PUBLIC_HEADER DESTINATION include/oqs-provider/
        )

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VENDOR "www.openquantumsafe.org")
set(CPACK_PACKAGE_VERSION ${OQSPROVIDER_VERSION_TEXT})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, openssl (>= 3.0.0)")
if (NOT "${LIBOQS_LIBRARY_TYPE}" STREQUAL "STATIC_LIBRARY")
  message("Adding liboqs as dynamic dependency for the debian package")
  string(APPEND CPACK_DEBIAN_PACKAGE_DEPENDS ", liboqs (>= 0.8.0)")
endif ()
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "www.openquantumsafe.org")
include(CPack)

if (OQS_PROVIDER_BUILD_STATIC)
  targets_set_static_provider(qkdkemprovider)
endif()
