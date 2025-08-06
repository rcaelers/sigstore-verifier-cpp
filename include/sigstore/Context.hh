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

#ifndef SIGSTORE_CONTEXT_HH
#define SIGSTORE_CONTEXT_HH

#include <memory>
#include <string>
#include <boost/outcome/std_result.hpp>

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  class Bundle;
  /**
   * @brief Interface for Sigstore certificate and transparency log context
   *
   * The Context interface defines the contract for managing
   * certificate stores and transparency log verification within the Sigstore
   * ecosystem. It provides the trusted certificate authority configuration
   * needed for bundle verification.
   *
   * @par Example Usage
   * @code
   * auto context = sigstore::Context::instance();
   * context->load_embedded_fulcio_ca_certificates();
   *
   * auto bundle = Bundle::create(bundle_json);
   * auto result = bundle->verify_blob(artifact_data, context);
   * if (result) {
   *     // Verification successful
   * } else {
   *     // Handle verification failure
   * }
   * @endcode
   */
  class Context
  {
  public:
    virtual ~Context() = default;

    Context(const Context &) = delete;
    Context &operator=(const Context &) = delete;
    Context(Context &&) = delete;
    Context &operator=(Context &&) = delete;

    /**
     * @brief Factory function to create a Context implementation
     *
     * Creates a concrete implementation of the Context interface.
     * This is the recommended way to obtain a context instance.
     *
     * @return std::shared_ptr<Context> A shared pointer to a context implementation
     *
     * @par Example
     * @code
     * auto context = sigstore::Context::instance();
     * context->load_embedded_fulcio_ca_certificates();
     * @endcode
     */
    static std::shared_ptr<Context> instance();

    /**
     * @brief Factory function to create a Context implementation
     *
     * Creates a concrete implementation of the Context interface.
     * This is the recommended way to obtain a context instance.
     *
     * @return std::shared_ptr<Context> A shared pointer to a context implementation
     *
     * @par Example
     * @code
     * auto context = sigstore::Context::instance();
     * context->load_embedded_fulcio_ca_certificates();
     * @endcode
     */
    static std::shared_ptr<Context> instance_default();

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
    virtual outcome::std_result<void> load_embedded_fulcio_ca_certificates() = 0;

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
     * auto result = context->add_ca_certificate(custom_ca);
     * @endcode
     */
    virtual outcome::std_result<void> add_ca_certificate(const std::string &ca_certificate) = 0;

  protected:
    Context() = default;
  };

} // namespace sigstore

#endif // SIGSTORE_CONTEXT_HH
