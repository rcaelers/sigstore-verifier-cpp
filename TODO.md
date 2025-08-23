# TODO - Sigstore Verifier C++

This file tracks planned improvements and enhancements for the sigstore-verifier-cpp library.

## High Priority

- [ ] Improved error reporting for programmatic error handling
- [ ] Online transparency log verification
- [ ] Better CA certificate management
  - [ ] Online retrieval of Fulcio and Rekor public keys
  - [ ] Setting custom Rekor certificates
- [ ] Improve API granularity
  - [X] Bundle verification API
  - [X] Artifact verification API
  - [X] Transparency log verification API

## Low Priority

- [ ] More Sigstore features
  - [ ] Support for DSSE (Dead Simple Signing Envelope)
  - [ ] In-toto attestation verification
