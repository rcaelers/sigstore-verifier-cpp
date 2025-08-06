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

#ifndef SIGSTORE_CERTIFICATE_HH
#define SIGSTORE_CERTIFICATE_HH

#include <string>
#include <vector>
#include <boost/outcome/std_result.hpp>
#include <openssl/x509.h>

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  class PublicKey;

  /**
   * @brief Cryptographic digest algorithms supported for signature verification
   */
  enum class DigestAlgorithm
  {
    SHA1,   ///< SHA-1 digest algorithm (deprecated, use SHA256 or higher)
    SHA256, ///< SHA-256 digest algorithm (recommended)
    SHA384, ///< SHA-384 digest algorithm
    SHA512  ///< SHA-512 digest algorithm
  };

  /**
   * @brief Public interface for X.509 certificate operations
   *
   * The CertificateInfo class provides a read-only interface to X.509 certificates,
   * offering methods to extract common certificate information and validate
   * certificate properties. This is the public API for certificate operations
   * within the Sigstore verification system.
   *
   * This interface focuses on the most commonly needed certificate operations
   * for signature verification scenarios, including:
   * - Subject information extraction
   * - OIDC issuer identification
   * - Certificate validation status
   * - Public key access
   * - Validity period checks
   *
   * @par Usage Example
   * @code
   * auto bundle = sigstore::load_bundle_from_file("signature.sigstore");
   * auto certificate = bundle->get_certificate();
   *
   * if (certificate) {
   *     std::cout << "Subject: " << certificate->subject_email() << std::endl;
   *     std::cout << "Issuer: " << certificate->oidc_issuer() << std::endl;
   *     std::cout << "Self-signed: " << certificate->is_self_signed() << std::endl;
   * }
   * @endcode
   */
  class CertificateInfo
  {
  public:
    virtual ~CertificateInfo() = default;

    CertificateInfo(const CertificateInfo &) = delete;
    CertificateInfo &operator=(const CertificateInfo &) = delete;
    CertificateInfo(CertificateInfo &&) = delete;
    CertificateInfo &operator=(CertificateInfo &&) = delete;

    /**
     * @brief Gets the subject email from the certificate
     *
     * Extracts the email address from the certificate's subject alternative name
     * extension or subject distinguished name.
     *
     * @return std::string The subject email address, empty string if not present
     *
     * @par Example
     * @code
     * auto email = certificate->subject_email();
     * if (!email.empty()) {
     *     std::cout << "Signed by: " << email << std::endl;
     * }
     * @endcode
     */
    virtual std::string subject_email() const = 0;

    /**
     * @brief Gets the OIDC issuer from the certificate
     *
     * Extracts the OpenID Connect issuer URL from the certificate extensions.
     * This identifies the identity provider that issued the signing certificate.
     *
     * @return std::string The OIDC issuer URL, empty string if not present
     *
     * @par Example
     * @code
     * auto issuer = certificate->oidc_issuer();
     * if (!issuer.empty()) {
     *     std::cout << "Issued by: " << issuer << std::endl;
     * }
     * @endcode
     */
    virtual std::string oidc_issuer() const = 0;

    /**
     * @brief Verifies a digital signature using this certificate
     *
     * Uses the certificate's public key to verify that the given signature
     * matches the provided data using the specified digest algorithm.
     *
     * @param data The data that was signed (as byte vector)
     * @param signature The signature to verify (as byte vector)
     * @param digest_algorithm The digest algorithm used for hashing (default: SHA256)
     * @return boost::outcome_v2::std_result<void> Success or error details
     *
     * @par Example
     * @code
     * std::vector<uint8_t> data = get_document_bytes();
     * std::vector<uint8_t> signature = get_signature_bytes();
     * auto result = certificate->verify_signature(data, signature);
     * if (result) {
     *     // Signature is valid
     * }
     * @endcode
     */
    virtual outcome::std_result<void> verify_signature(const std::vector<uint8_t> &data,
                                                       const std::vector<uint8_t> &signature,
                                                       DigestAlgorithm digest_algorithm = DigestAlgorithm::SHA256) const = 0;

    /**
     * @brief Verifies a digital signature using this certificate (string version)
     *
     * Convenience method for verifying signatures when data and signature
     * are available as strings. Internally converts to byte vectors.
     *
     * @param data The data that was signed (as string)
     * @param signature The signature to verify (as string)
     * @param digest_algorithm The digest algorithm used for hashing (default: SHA256)
     * @return boost::outcome_v2::std_result<void> Success or error details
     *
     * @par Example
     * @code
     * std::string data = "document content";
     * std::string signature = get_signature_string();
     * auto result = certificate->verify_signature(data, signature);
     * if (result) {
     *     // Signature is valid
     * }
     * @endcode
     */
    virtual outcome::std_result<void> verify_signature(const std::string &data,
                                                       const std::string &signature,
                                                       DigestAlgorithm digest_algorithm = DigestAlgorithm::SHA256) const = 0;

    /**
     * @brief Gets the underlying OpenSSL X509 certificate object
     *
     * Returns a pointer to the OpenSSL X509 structure that represents this certificate.
     * This provides direct access to the OpenSSL certificate for applications that need
     * to perform low-level certificate operations or integrate with other OpenSSL-based code.
     *
     * @return X509* Pointer to the OpenSSL X509 certificate object (non-owning pointer)
     *         The certificate object remains valid for the lifetime of this CertificateInfo instance
     *
     * @warning The returned pointer should not be freed by the caller. The certificate
     *          object is managed by the CertificateInfo implementation.
     *
     * @par Example
     * @code
     * X509* x509_cert = certificate->get_x509();
     * if (x509_cert) {
     *     // Extract additional certificate information using OpenSSL functions
     *     X509_NAME* subject = X509_get_subject_name(x509_cert);
     *     // ... other OpenSSL operations
     * }
     * @endcode
     */
    virtual X509 *get_x509() const = 0;

  protected:
    CertificateInfo() = default;
  };

} // namespace sigstore

#endif // SIGSTORE_CERTIFICATE_HH
