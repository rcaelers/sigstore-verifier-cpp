set(SIGSTORE_REV  v0.5.0)
set(GOOGLEAPIS_REV f37bfb8159ea687e6c2a6b587f5cf1dada04b9f8)

FetchContent_Declare(sigstore_protos
    GIT_REPOSITORY  https://github.com/sigstore/protobuf-specs.git
    GIT_TAG         ${SIGSTORE_REV}
    GIT_SHALLOW    TRUE
)
FetchContent_Declare(googleapis_protos
    GIT_REPOSITORY  https://github.com/googleapis/googleapis.git
    GIT_TAG         ${GOOGLEAPIS_REV}
    GIT_SHALLOW    FALSE
)

FetchContent_MakeAvailable(sigstore_protos googleapis_protos)

set(SIGSTORE_PROTO_DIR   ${sigstore_protos_SOURCE_DIR})
set(GOOGLEAPIS_PROTO_DIR ${googleapis_protos_SOURCE_DIR})
set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

file(MAKE_DIRECTORY ${GENERATED_DIR})

set(Protobuf_IMPORT_DIRS
    ${SIGSTORE_PROTO_DIR}/protos
    ${GOOGLEAPIS_PROTO_DIR}
)

set(SIGSTORE_PROTO_FILES
     ${SIGSTORE_PROTO_DIR}/protos/sigstore_bundle.proto
     ${SIGSTORE_PROTO_DIR}/protos/sigstore_rekor.proto
     ${SIGSTORE_PROTO_DIR}/protos/envelope.proto
     ${SIGSTORE_PROTO_DIR}/protos/sigstore_common.proto
)

protobuf_generate(
    LANGUAGE cpp
    OUT_VAR   SIGSTORE_PROTO_SRCS
    IMPORT_DIRS ${Protobuf_IMPORT_DIRS} ${Protobuf_INCLUDE_DIRS}
    PROTOC_OUT_DIR ${GENERATED_DIR}
    PROTOS   ${SIGSTORE_PROTO_FILES}
)
set(GOOGLEAPIS_PROTO_FILES
    ${GOOGLEAPIS_PROTO_DIR}/google/api/field_behavior.proto
)

protobuf_generate(
    LANGUAGE cpp
    OUT_VAR   GOOGLEAPI_PROTO_SRCS
    IMPORT_DIRS ${Protobuf_IMPORT_DIRS} ${Protobuf_INCLUDE_DIRS}
    PROTOC_OUT_DIR ${GENERATED_DIR}
    PROTOS   ${GOOGLEAPIS_PROTO_FILES}
)

add_library(sigstore OBJECT)

target_sources(sigstore PRIVATE
  Base64.cc
  Logging.cc
  BundleHelper.cc
  BundleLoader.cc
  CanonicalBodyParser.cc
  Certificate.cc
  CertificateStore.cc
  CheckpointParser.cc
  CryptographicAlgorithms.cc
  MerkleTreeValidator.cc
  PublicKey.cc
  RFC6962Hasher.cc
  SigstoreErrors.cc
  SigstoreVerifier.cc
  TransparencyLogLoader.cc
  TransparencyLogVerifier.cc
  ${SIGSTORE_PROTO_SRCS}
  ${GOOGLEAPI_PROTO_SRCS}
)

target_link_libraries(sigstore PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto Boost::json)
target_link_libraries(sigstore PUBLIC protobuf::libprotobuf absl::base absl::status absl::strings)

target_include_directories(
  sigstore
  PRIVATE
  ${PROJECT_SOURCE_DIR}/src
  ${PROJECT_SOURCE_DIR}/include
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${PROJECT_SOURCE_DIR}/include
  $<BUILD_INTERFACE:${GENERATED_DIR}>
  $<BUILD_INTERFACE:${SIGSTORE_PROTO_DIR}>
  $<BUILD_INTERFACE:${GOOGLEAPIS_PROTO_DIR}>
)

target_code_coverage(sigstore ALL AUTO)
