# CMake generated Testfile for 
# Source directory: /home/dsobral/Repos/qkd-kem-provider/test
# Build directory: /home/dsobral/Repos/qkd-kem-provider/build/test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(oqs_kems "/home/dsobral/Repos/qkd-kem-provider/build/test/oqs_test_kems" "qkdkemprovider" "/home/dsobral/Repos/qkd-kem-provider/test/oqs.cnf")
set_tests_properties(oqs_kems PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/dsobral/Repos/qkd-kem-provider/build/lib" _BACKTRACE_TRIPLES "/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;12;add_test;/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;0;")
add_test(oqs_groups "/home/dsobral/Repos/qkd-kem-provider/build/test/oqs_test_groups" "qkdkemprovider" "/home/dsobral/Repos/qkd-kem-provider/test/oqs.cnf" "/home/dsobral/Repos/qkd-kem-provider/test")
set_tests_properties(oqs_groups PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/dsobral/Repos/qkd-kem-provider/build/lib" _BACKTRACE_TRIPLES "/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;42;add_test;/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;0;")
add_test(oqs_endecode "/home/dsobral/Repos/qkd-kem-provider/build/test/oqs_test_endecode" "qkdkemprovider" "/home/dsobral/Repos/qkd-kem-provider/test/openssl-ca.cnf")
set_tests_properties(oqs_endecode PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/dsobral/Repos/qkd-kem-provider/build/lib" _BACKTRACE_TRIPLES "/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;65;add_test;/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;0;")
add_test(oqs_evp_pkey_params "/home/dsobral/Repos/qkd-kem-provider/build/test/oqs_test_evp_pkey_params" "qkdkemprovider" "/home/dsobral/Repos/qkd-kem-provider/test/openssl-ca.cnf")
set_tests_properties(oqs_evp_pkey_params PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/dsobral/Repos/qkd-kem-provider/build/lib" _BACKTRACE_TRIPLES "/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;86;add_test;/home/dsobral/Repos/qkd-kem-provider/test/CMakeLists.txt;0;")
