add_executable(test-sigstore
  BundleLoaderTest.cc
  BundleTest.cc
  CanonicalBodyParserTest.cc
  CertificateStoreTest.cc
  CertificateTest.cc
  CheckpointParserTest.cc
  PublicKeyTest.cc
  RFC6962HasherTest.cc
  SigstoreTest.cc
  TransparencyLogLoaderTest.cc
)

target_link_libraries(test-sigstore
  PRIVATE
  sigstore
  GTest::gtest_main
  GTest::gmock_main
  spdlog::spdlog
  OpenSSL::SSL
  OpenSSL::Crypto
  Boost::json
)
target_include_directories(test-sigstore
  PRIVATE
  ${PROJECT_SOURCE_DIR}/src
  ${PROJECT_SOURCE_DIR}/include
)

target_code_coverage(test-sigstore AUTO ALL)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-sigstore.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-sigstore.xml.sigstore.new.bundle" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/body.json" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/tlog.json" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/corrupted.json" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

add_test(NAME test-sigstore COMMAND test-sigstore)
target_code_coverage(test-sigstore AUTO ALL)

if(WIN32)
  set_tests_properties(test-sigstore PROPERTIES ENVIRONMENT "PATH=${TEST_PATH_ENV}")
endif()
