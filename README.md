# Sigstore Verifier C++

A C++ library for verifying artifacts signed with the [Sigstore](https://sigstore.dev/) ecosystem. This library provides high-level verification support for validating digital signatures. The main goal is to verify the authenticity and integrity of signed software installers by the [Unfold](https://github.com/rcaelers/unfold) auto-update framework.

## Overview

Sigstore Verifier C++ implements the verification components of the Sigstore ecosystem, allowing applications to validate the authenticity and integrity of signed artifacts. The library focuses on **high-level verification operations** and provides a simple API for common verification workflows.

### Supported Verification Operations

The library provides verification for:

- Sigstore bundle format validation and parsing
- Certificate chain verification against Fulcio CA
- Digital signature validation using embedded certificates
- Transparency log inclusion proof verification
- Checkpoint validation with cryptographic signatures
- Identity constraints verification (email/issuer matching)

### Dependencies

- **CMake** 3.23 or higher
- **C++20** compatible compiler
- **OpenSSL** version 3 or higher
- **Boost** (for JSON parsing and outcome error handling)
- **Protocol Buffers** (automatically fetched, if not already installed)
- **Abseil C++** (automatically fetched, if not already installed)
- **spdlog** (for logging)
- **Sigstore Protocol Buffers** (v0.5.0, automatically fetched)
- **Google APIs Protocol Buffers** (automatically fetched)
- **GoogleTest** (for testing)

### Basic Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Running Tests

```bash
cd build
ctest --output-on-failure
```

## Usage

### Basic Verification

```cpp
#include <sigstore/Context.hh>
#include <sigstore/Bundle.hh>
#include <iostream>
#include <fstream>

int main() {
    // Create context instance
    auto context = sigstore::Context::instance();

    // Load embedded Fulcio CA certificates
    auto load_result = context->load_embedded_fulcio_ca_certificates();
    if (!load_result) {
        std::cerr << "Failed to load CA certificates: "
                  << load_result.error().message() << std::endl;
        return 1;
    }

    // Read artifact data
    std::string artifact_data = "Hello, World!";

    // Read bundle file
    std::ifstream bundle_file("artifact.sigstore");
    if (!bundle_file.is_open()) {
        std::cerr << "Failed to open bundle file" << std::endl;
        return 1;
    }
    std::string bundle_json((std::istreambuf_iterator<char>(bundle_file)),
                           std::istreambuf_iterator<char>());
    bundle_file.close();

    // Create bundle and verify the artifact
    auto bundle_result = sigstore::Bundle::create(context, bundle_json);
    if (!bundle_result) {
        std::cerr << "Failed to create bundle: "
                  << bundle_result.error().message() << std::endl;
        return 1;
    }

    auto bundle = bundle_result.value();
    auto result = bundle->verify(artifact_data);
    if (result) {
        std::cout << "Verification successful!" << std::endl;
    } else {
        std::cerr << "Verification failed: "
                  << result.error().message() << std::endl;
    }

    return 0;
}
```

### Identity-Constrained Verification

```cpp
auto context = sigstore::Context::instance();
context->load_embedded_fulcio_ca_certificates();

// Read bundle file
std::ifstream bundle_file("artifact.sigstore");
std::string bundle_json((std::istreambuf_iterator<char>(bundle_file)),
                       std::istreambuf_iterator<char>());
bundle_file.close();

auto bundle_result = sigstore::Bundle::create(context, bundle_json);
if (!bundle_result) {
    std::cerr << "Failed to create bundle" << std::endl;
    return 1;
}

auto bundle = bundle_result.value();

// Get certificate information to check identity
auto cert_info = bundle->get_certificate_info();
if (cert_info) {
    // Check if certificate matches expected identity
    // Implementation depends on certificate validation requirements
}

auto result = bundle->verify(artifact_data);
// Verification succeeds based on the bundle's embedded certificate
```

### Error Handling

The library uses `boost::outcome::std_result<T>` for error handling:

```cpp
auto context = sigstore::Context::instance();
context->load_embedded_fulcio_ca_certificates();

std::ifstream bundle_file("artifact.sigstore");
std::string bundle_json((std::istreambuf_iterator<char>(bundle_file)),
                       std::istreambuf_iterator<char>());
bundle_file.close();

auto bundle_result = sigstore::Bundle::create(context, bundle_json);
if (bundle_result) {
    auto bundle = bundle_result.value();
    auto result = bundle->verify(data);
    if (result) {
        // Success
        std::cout << "Verification passed" << std::endl;
    } else {
        // Error
        std::cerr << "Error: " << result.error().message() << std::endl;
    }
} else {
    std::cerr << "Bundle creation failed: " << bundle_result.error().message() << std::endl;
}
```

### Supported Error Types

- `InvalidBundle` - Malformed or invalid Sigstore bundle
- `InvalidSignature` - Digital signature verification failed
- `InvalidCertificate` - Certificate parsing or validation failed
- `InvalidPublicKey` - Public key format or validation error
- `InvalidTransparencyLog` - Transparency log verification failed
- `JsonParseError` - JSON parsing error
- `SystemError` - System-level error
- `InvalidBase64` - Base64 decoding error

## Integration

### CMake Integration

```cmake
find_package(SigstoreVerifier REQUIRED)
target_link_libraries(your_target PRIVATE SigstoreVerifier::sigstore)
```

## Limitations

This library provides **high-level verification support only**. It does not include:

- **Signing capabilities** - Only verification is supported
- **Bundle creation** - Cannot create new Sigstore bundles
- **Key generation** - No cryptographic key generation utilities
- **Low-level cryptographic primitives** - Focuses on Sigstore-specific operations
- **Online operations** - No direct integration with Sigstore services (Fulcio, Rekor)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
