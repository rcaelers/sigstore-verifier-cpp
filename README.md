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
#include <sigstore/SigstoreVerifier.hh>
#include <iostream>
#include <fstream>

int main() {
    // Create verifier instance
    sigstore::SigstoreVerifier verifier;

    // Load embedded Fulcio CA certificates
    auto load_result = verifier.load_embedded_fulcio_ca_certificates();
    if (!load_result) {
        std::cerr << "Failed to load CA certificates: "
                  << load_result.error().message() << std::endl;
        return 1;
    }

    // Read artifact and bundle
    std::string artifact_data = "Hello, World!";
    std::string bundle_json = read_bundle_file("artifact.sigstore");

    // Verify the artifact
    auto result = verifier.verify_blob(artifact_data, bundle_json);
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
sigstore::SigstoreVerifier verifier;
verifier.load_embedded_fulcio_ca_certificates();

// Only accept signatures from specific identities
verifier.add_expected_identity("user@example.com", "https://github.com/login/oauth");
verifier.add_expected_identity("user@gmail.com", "https://accounts.google.com");

auto result = verifier.verify_blob(artifact_data, bundle_json);
// Verification succeeds only if the certificate matches one of the expected identities
```

### Custom CA Certificates

```cpp
sigstore::SigstoreVerifier verifier;

// Load custom CA certificate
std::string custom_ca = read_pem_file("custom-ca.pem");
auto ca_result = verifier.add_ca_certificate(custom_ca);

if (ca_result) {
    // Proceed with verification
    auto result = verifier.verify_blob(artifact_data, bundle_json);
}
```

### Error Handling

The library uses `boost::outcome::std_result<T>` for error handling:

```cpp
auto result = verifier.verify_blob(data, bundle);
if (result) {
    // Success
    std::cout << "Verification passed" << std::endl;
} else {
    // Error
    std::cerr << "Error: " << result.error().message() << std::endl;
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
