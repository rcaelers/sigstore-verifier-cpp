// Copyright (C) 2025 Rob Caelers <rob.caelers@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef SIGSTORE_VERIFIER_HH
#define SIGSTORE_VERIFIER_HH

#include <string>
#include <string_view>
#include <memory>
#include <boost/outcome/std_result.hpp>

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  /**
   * @brief Verification engine for Sigstore-signed artifacts
   *
   * The SigstoreVerifier class implements verification of artifacts
   * signed within the Sigstore ecosystem. It performs validation of digital
   * signatures, certificate chains, and transparency log entries.
   *
   * @par Thread Safety
   * This class is not thread-safe. Each thread should use its own instance.
   *
   * @par Example Usage
   * @code
   * sigstore::SigstoreVerifier verifier;
   * verifier.load_embedded_fulcio_ca_certificates();
   * verifier.add_expected_identity("user@example.com", "https://github.com/login/oauth");
   *
   * auto result = verifier.verify_blob(artifact_data, bundle_json);
   * if (result) {
   *     // Verification successful
   * } else {
   *     // Handle verification failure
   * }
   * @endcode
   */
  class SigstoreVerifier
  {
  public:
    explicit SigstoreVerifier();
    ~SigstoreVerifier();

    SigstoreVerifier(const SigstoreVerifier &) = delete;
    SigstoreVerifier &operator=(const SigstoreVerifier &) = delete;
    SigstoreVerifier(SigstoreVerifier &&) noexcept;
    SigstoreVerifier &operator=(SigstoreVerifier &&) noexcept;

    /**
     * @brief Verifies an artifact against its Sigstore bundle
     *
     * Validates a signed artifact by checking:
     * - Digital signature validity
     * - Certificate chain verification
     * - Transparency log validation
     * - Identity verification (if configured)
     *
     * @param data The artifact data to verify
     * @param bundle_json JSON-encoded Sigstore bundle containing
     *                   signature, certificate, and transparency log data
     *
     * @return outcome::std_result<void> Success on valid verification,
     *         error with failure details otherwise
     *
     * @par Preconditions
     * - CA certificates must be loaded via load_embedded_fulcio_ca_certificates()
     *   or add_ca_certificate()
     * - bundle_json must conform to Sigstore bundle format
     *
     * @par Example
     * @code
     * std::string artifact = "Hello, World!";
     * std::string bundle = read_bundle_file("artifact.sigstore");
     * auto result = verifier.verify_blob(artifact, bundle);
     * @endcode
     */
    outcome::std_result<void> verify_blob(std::string_view data, std::string_view bundle_json);

    /**
     * @brief Loads embedded Fulcio CA certificates
     *
     * Initializes the trust store with the default Fulcio certificate
     * authority certificates embedded in the library. These certificates
     * validate certificate chains in Sigstore bundles.
     *
     * @return outcome::std_result<void> Success on successful loading,
     *         error on failure
     *
     * @note Should be called before verification operations
     * @see add_ca_certificate() for adding custom CA certificates
     */
    outcome::std_result<void> load_embedded_fulcio_ca_certificates();

    /**
     * @brief Adds a CA certificate to the trust store
     *
     * Appends a certificate authority certificate to the verifier's
     * trust store. Used for custom or updated CA certificates
     * beyond the embedded defaults.
     *
     * @param ca_certificate PEM-encoded CA certificate
     *
     * @return outcome::std_result<void> Success on valid certificate addition,
     *         error if certificate is invalid or parsing fails
     *
     * @par Example
     * @code
     * std::string custom_ca = read_file("custom-ca.pem");
     * auto result = verifier.add_ca_certificate(custom_ca);
     * @endcode
     */
    outcome::std_result<void> add_ca_certificate(const std::string &ca_certificate);

    /**
     * @brief Adds an expected identity constraint
     *
     * Configures the verifier to accept signatures only from a specified
     * email address and OIDC issuer combination. Multiple identities may
     * be configured; verification succeeds if any configured identity matches.
     *
     * @param email Expected email address in certificate subject
     * @param issuer Expected OIDC issuer URL
     *
     * @par Example
     * @code
     * // Accept signatures from this GitHub user
     * verifier.add_expected_identity("user@example.com", "https://github.com/login/oauth");
     *
     * // Also accept from Google accounts
     * verifier.add_expected_identity("user@gmail.com", "https://accounts.google.com");
     * @endcode
     *
     * @see remove_expected_identity(), clear_expected_certificate_identities()
     */
    void add_expected_identity(const std::string &email, const std::string &issuer);

    /**
     * @brief Removes an expected identity constraint
     *
     * Removes a previously configured identity constraint. The specified
     * email/issuer combination will no longer be accepted during verification
     * unless it matches another configured identity.
     *
     * @param email Email address to remove from expected identities
     * @param issuer OIDC issuer to remove from expected identities
     *
     * @note No effect if the email/issuer combination was not previously configured
     *
     * @see add_expected_identity(), clear_expected_certificate_identities()
     */
    void remove_expected_identity(const std::string &email, const std::string &issuer);

    /**
     * @brief Clears all expected identity constraints
     *
     * Removes all configured identity constraints. Subsequently, the verifier
     * will accept signatures from any certificate with a valid chain,
     * regardless of subject email or OIDC issuer.
     *
     * @warning Disables identity verification, reducing security constraints
     *
     * @see add_expected_identity(), remove_expected_identity()
     */
    void clear_expected_certificate_identities();

  private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
  };

} // namespace sigstore

#endif // SIGSTORE_VERIFIER_HH
