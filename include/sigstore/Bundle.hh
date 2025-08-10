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

#ifndef SIGSTORE_BUNDLE_HH
#define SIGSTORE_BUNDLE_HH

#include <memory>
#include <string_view>
#include <boost/outcome/std_result.hpp>

#include "Certificate.hh"
#include "sigstore_bundle.pb.h"

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  class Context;

  /**
   * @brief Interface for Sigstore bundle representation
   *
   * The Bundle interface provides access to the contents of a parsed Sigstore bundle.
   * This interface wraps the internal bundle representation and provides a clean API
   * for accessing bundle data.
   *
   * @par Example Usage
   * @code
   * auto bundle_result = Bundle::load_bundle(bundle_json);
   * if (bundle_result) {
   *     auto bundle = bundle_result.value();
   *     auto certificate = bundle->get_certificate_info();
   * }
   * @endcode
   */
  class Bundle
  {
  public:
    virtual ~Bundle() = default;

    Bundle(const Bundle &) = delete;
    Bundle &operator=(const Bundle &) = delete;
    Bundle(Bundle &&) = delete;
    Bundle &operator=(Bundle &&) = delete;

    /**
     * @brief Loads and parses a Sigstore bundle from JSON
     *
     * Static factory method that parses a JSON-encoded Sigstore bundle and returns
     * a Bundle instance for accessing its contents. This function validates the bundle
     * format and structure. The returned Bundle is guaranteed to be valid and parseable.
     *
     * @param context The context to use for loading the bundle
     * @param bundle_json JSON-encoded Sigstore bundle string
     *
     * @return outcome::std_result<std::shared_ptr<Bundle>> A shared pointer
     *         to the parsed Bundle on success, error on parsing failure
     *
     * @par Example
     * @code
     * std::string bundle_json = read_bundle_file("artifact.sigstore");
     * auto bundle_result = Bundle::create(bundle_json);
     * if (bundle_result) {
     *     auto bundle = bundle_result.value();
     *     auto certificate = bundle->get_certificate_info();
     * }
     * @endcode
     */
    static outcome::std_result<std::shared_ptr<Bundle>> create(std::shared_ptr<Context> context, std::string_view bundle_json);

    /**
     * @brief Verifies an artifact against this Sigstore bundle
     *
     * Validates a signed artifact by checking:
     * - Digital signature validity
     * - Certificate chain verification
     * - Transparency log validation
     *
     * @param data The artifact data to verify
     *
     * @return outcome::std_result<void> Success on valid verification,
     *         error with failure details otherwise
     *
     * @par Example
     * @code
     * std::string artifact = "Hello, World!";
     * auto context = sigstore::Context::instance();
     * context->load_embedded_fulcio_ca_certificates();
     * auto result = bundle->verify_blob(artifact);
     * @endcode
     */
    virtual outcome::std_result<void> verify(const std::string_view &data) = 0;

    virtual outcome::std_result<void> verify_signature(const std::string_view &data) const = 0;
    virtual outcome::std_result<void> verify_transparency_log_offline() const = 0;

    /**
     * @brief Gets the signing certificate from the bundle
     *
     * Retrieves the certificate used to create the signature. This certificate
     * contains the public key and identity information about the signer.
     *
     * @return std::shared_ptr<Certificate> Pointer to the certificate,
     *         nullptr if no certificate is present
     *
     * @par Example
     * @code
     * auto certificate = bundle->get_certificate();
     * if (certificate) {
     *     // Access certificate details
     * }
     * @endcode
     */
    virtual std::shared_ptr<CertificateInfo> get_certificate_info() const = 0;

    /**
     * @brief Gets the underlying protobuf Bundle object
     *
     * Returns a reference to the protobuf Bundle object that represents the complete
     * Sigstore bundle data structure. This provides direct access to all bundle
     * fields and allows integration with other protobuf-based systems.
     *
     * @return const dev::sigstore::bundle::v1::Bundle& Reference to the protobuf Bundle object
     *         The bundle object remains valid for the lifetime of this Bundle instance
     *
     * @par Example
     * @code
     * const auto& proto_bundle = bundle->get_bundle();
     * // Access protobuf fields directly
     * std::cout << "Media type: " << proto_bundle.media_type() << std::endl;
     * // Work with transparency log entries
     * for (const auto& entry : proto_bundle.verification_material().tlog_entries()) {
     *     // Process transparency log entries
     * }
     * @endcode
     */
    virtual const dev::sigstore::bundle::v1::Bundle &get_bundle() const = 0;

  protected:
    Bundle() = default;
  };

} // namespace sigstore

#endif // SIGSTORE_BUNDLE_HH
