add_executable(provider_to_provider_test provider_to_provider_test.c)
target_link_libraries(provider_to_provider_test PRIVATE
  OpenSSL::Crypto ${QKD_ETSI_API_TARGET})
target_compile_definitions(provider_to_provider_test PRIVATE
  $<$<BOOL:${ETSI_004_API}>:ETSI_004_API>
  $<$<BOOL:${ETSI_014_API}>:ETSI_014_API>
  $<$<BOOL:${QKD_KEY_ID_CH}>:QKD_KEY_ID_CH>)

set(qkdkem_test_environment
  "OPENSSL_MODULES=$<TARGET_FILE_DIR:qkdkemprovider>"
  "LD_LIBRARY_PATH=$<TARGET_FILE_DIR:${QKD_ETSI_API_TARGET}>:$<TARGET_FILE_DIR:OpenSSL::Crypto>:$ENV{LD_LIBRARY_PATH}"
  "QKD_MASTER_KME_HOSTNAME=master.example"
  "QKD_SLAVE_KME_HOSTNAME=slave.example"
  "QKD_MASTER_SAE=alice"
  "QKD_SLAVE_SAE=bob"
  "QKD_SOURCE_URI=source.example"
  "QKD_DEST_URI=destination.example")

add_test(NAME provider_to_provider COMMAND provider_to_provider_test)
set_tests_properties(provider_to_provider PROPERTIES ENVIRONMENT
  "${qkdkem_test_environment}")

add_executable(tls_test tls_test.c tlstest_helpers.c)
target_link_libraries(tls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_test(NAME tls_qkd_mlkem768
  COMMAND tls_test "${CMAKE_CURRENT_SOURCE_DIR}/servercert.pem"
                   "${CMAKE_CURRENT_SOURCE_DIR}/serverkey.pem")
set_tests_properties(tls_qkd_mlkem768 PROPERTIES ENVIRONMENT
  "${qkdkem_test_environment}")
