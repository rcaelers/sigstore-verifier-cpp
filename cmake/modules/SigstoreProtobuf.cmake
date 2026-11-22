# Protobuf libraries belong to the target platform; protoc runs on the host.
# Use the standard FindProtobuf override for toolchains that provide a host tool.
if(CMAKE_CROSSCOMPILING)
  find_program(Protobuf_PROTOC_EXECUTABLE NAMES protoc
    NO_CMAKE_FIND_ROOT_PATH NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH NO_PACKAGE_ROOT_PATH
    REQUIRED)
endif()
set(_sigstore_protoc_executable "${Protobuf_PROTOC_EXECUTABLE}")

# Protobuf's package version may use its release number (36.2.0) or its
# language-specific C++ version (7.36.2). Do not reject a compatible config
# based on the different numbering conventions.
find_package(Protobuf QUIET CONFIG)
if(NOT Protobuf_FOUND)
  message(STATUS "Protobuf not found, fetching compatible version...")
  set(protobuf_BUILD_TESTS OFF)
  set(protobuf_BUILD_SHARED_LIBS ON)
  set(protobuf_BUILD_EXPORT OFF)
  set(protobuf_MSVC_STATIC_RUNTIME OFF)
  if(CMAKE_CROSSCOMPILING)
    set(protobuf_BUILD_PROTOC_BINARIES OFF)
  else()
    set(protobuf_BUILD_PROTOC_BINARIES ON)
  endif()

  set(_sigstore_saved_cxx_flags "${CMAKE_CXX_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
  FetchContent_Declare(protobuf
    GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
    GIT_TAG v36.2
    GIT_SHALLOW TRUE
    OVERRIDE_FIND_PACKAGE)
  FetchContent_MakeAvailable(protobuf)
  set(CMAKE_CXX_FLAGS "${_sigstore_saved_cxx_flags}")
  set(_sigstore_protobuf_version "36.2")
else()
  set(_sigstore_protobuf_version "${Protobuf_VERSION}")
  if(NOT _sigstore_protobuf_version)
    set(_sigstore_protobuf_version "${protobuf_VERSION}")
  endif()
endif()

# An ancestor may have made the sources available through a package redirect.
# In that case its generated config need not include the generator helper.
if(NOT COMMAND protobuf_generate AND protobuf_SOURCE_DIR)
  include("${protobuf_SOURCE_DIR}/cmake/protobuf-generate.cmake")
endif()
if(NOT COMMAND protobuf_generate)
  message(FATAL_ERROR "The selected Protobuf package does not provide protobuf_generate")
endif()
if(protobuf_SOURCE_DIR)
  list(APPEND Protobuf_INCLUDE_DIRS "${protobuf_SOURCE_DIR}/src")
endif()

function(_sigstore_protobuf_release version output)
  if(version MATCHES "^([0-9]+)\\.([0-9]+)(\\.([0-9]+))?$")
    set(major "${CMAKE_MATCH_1}")
    set(minor "${CMAKE_MATCH_2}")
    set(patch "${CMAKE_MATCH_4}")
    if(major GREATER_EQUAL 4 AND major LESS 10 AND minor GREATER_EQUAL 22)
      set(version "${minor}.${patch}")
    elseif(major GREATER_EQUAL 22 AND (NOT patch OR patch EQUAL 0))
      set(version "${major}.${minor}")
    endif()
  endif()
  set(${output} "${version}" PARENT_SCOPE)
endfunction()

set(SIGSTORE_PROTOC_ARGS "")
if(_sigstore_protoc_executable)
  execute_process(COMMAND "${_sigstore_protoc_executable}" --version
    RESULT_VARIABLE _sigstore_protoc_result
    OUTPUT_VARIABLE _sigstore_protoc_version OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE _sigstore_protoc_error)
  if(NOT _sigstore_protoc_result EQUAL 0 OR
     NOT _sigstore_protoc_version MATCHES "^libprotoc ([0-9]+\\.[0-9]+(\\.[0-9]+)?)")
    message(FATAL_ERROR
      "Protobuf_PROTOC_EXECUTABLE must run on the build host: ${_sigstore_protoc_executable}\n"
      "${_sigstore_protoc_result}: ${_sigstore_protoc_error}")
  endif()
  _sigstore_protobuf_release("${CMAKE_MATCH_1}" _sigstore_protoc_release)
  _sigstore_protobuf_release("${_sigstore_protobuf_version}" _sigstore_library_release)
  if(_sigstore_library_release AND
     NOT _sigstore_protoc_release STREQUAL _sigstore_library_release)
    message(FATAL_ERROR
      "Host protoc ${_sigstore_protoc_release} does not match target Protobuf "
      "${_sigstore_library_release}. Set Protobuf_PROTOC_EXECUTABLE to a matching host tool.")
  endif()
  set(SIGSTORE_PROTOC_ARGS PROTOC_EXE "${_sigstore_protoc_executable}")
  message(STATUS "Sigstore: using host protoc ${_sigstore_protoc_executable} (${_sigstore_protoc_release})")
endif()
