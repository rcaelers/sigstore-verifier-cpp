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

#include "sigstore/SigstoreVerifier.hh"

#include "BundleHelper.hh"
#include "BundleLoader.hh"
#include "TransparencyLogVerifier.hh"
#include "CertificateStore.hh"

#include <memory>
#include <algorithm>
#include <boost/json.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "Logging.hh"
#include "sigstore/SigstoreErrors.hh"

#include "sigstore_bundle.pb.h"
#include "embedded_trust_bundle.h"

namespace sigstore
{

  class SigstoreVerifier::Impl
  {
  public:
    explicit Impl()
      : transparency_log_verifier_(std::make_unique<TransparencyLogVerifier>())
      , logger_(Logging::create("sigstore"))
      , certificate_store_(std::make_shared<CertificateStore>())
    {
    }

  public:
    outcome::std_result<dev::sigstore::bundle::v1::Bundle> parse_bundle(const std::string &bundle_json)
    {
      SigstoreBundleLoader loader;
      auto bundle_result = loader.load_from_json(bundle_json);
      if (!bundle_result)
        {
          logger_->error("Failed to parse sigstore bundle: {}", bundle_result.error().message());
          return bundle_result.error();
        }
      return bundle_result.value();
    }

    outcome::std_result<void> verify_signature(const std::string_view &content, const dev::sigstore::bundle::v1::Bundle &bundle)
    {
      BundleHelper helper(bundle);
      auto certificate = helper.get_certificate();
      const auto &signature = helper.get_signature();

      std::vector<uint8_t> signature_bytes;
      signature_bytes.assign(signature.begin(), signature.end());

      std::vector<uint8_t> content_bytes(content.begin(), content.end());
      return certificate->verify_signature(content_bytes, signature_bytes);
    }

    outcome::std_result<void> verify_certificate_chain(const dev::sigstore::bundle::v1::Bundle &bundle)
    {
      BundleHelper helper(bundle);
      auto cert = helper.get_certificate();
      return certificate_store_->verify_certificate_chain(cert);
    }

    outcome::std_result<void> verify(std::string_view data, std::string_view bundle_json)
    {
      std::string bundle_str(bundle_json);

      auto bundle_result = parse_bundle(bundle_str);
      if (!bundle_result)
        {
          logger_->error("Failed to parse sigstore bundle");
          return bundle_result.error();
        }

      auto bundle = bundle_result.value();

      auto verify_result = verify_signature(data, bundle);
      if (!verify_result)
        {
          logger_->error("Signature verification failed: {}", verify_result.error().message());
          return verify_result.error();
        }

      auto chain_result = verify_certificate_chain(bundle);
      if (!chain_result)
        {
          logger_->error("Certificate chain verification failed: {}", chain_result.error().message());
          return chain_result.error();
        }

      BundleHelper bundle_helper(bundle);
      auto tlog = bundle_helper.get_transparency_log_entries();

      if (tlog.empty())
        {
          logger_->warn("No transparency log entries found in bundle");
          return SigstoreError::InvalidTransparencyLog;
        }

      auto &entry = tlog[0];
      auto log_result = transparency_log_verifier_->verify_transparency_log(entry, bundle_helper.get_certificate(), get_expected_identities());

      if (!log_result)
        {
          logger_->error("Transparency log verification failed: {}", log_result.error().message());
          return log_result.error();
        }

      return outcome::success();
    }

    outcome::std_result<void> load_embedded_fulcio_ca_certificates()
    {
      logger_->debug("Loading embedded Fulcio CA certificates using CertificateStore");

      std::string trust_bundle_json{embedded_trust_bundle};

      auto certificate_store_res = certificate_store_->load_trust_bundle(trust_bundle_json);
      if (!certificate_store_res)
        {
          logger_->error("Failed to load embedded Fulcio CA certificates: {}", certificate_store_res.error().message());
          return certificate_store_res.error();
        }

      return outcome::success();
    }

    outcome::std_result<void> add_ca_certificates(const std::string &ca_certificate)
    {
      logger_->debug("Adding CA certificates to CertificateStore");

      auto result = certificate_store_->add_ca_certificates(ca_certificate);
      if (!result)
        {
          logger_->error("Failed to add CA certificates: {}", result.error().message());
          return result.error();
        }

      return outcome::success();
    }

    void add_expected_identity(const std::string &email, const std::string &issuer)
    {
      expected_identities_.emplace_back(email, issuer);
      logger_->debug("Added expected certificate identity: email='{}', issuer='{}'", email, issuer);
    }

    void remove_expected_identity(const std::string &email, const std::string &issuer)
    {
      auto it = std::find(expected_identities_.begin(), expected_identities_.end(), std::make_pair(email, issuer));
      if (it != expected_identities_.end())
        {
          expected_identities_.erase(it);
          logger_->debug("Removed expected certificate identity: email='{}', issuer='{}'", email, issuer);
        }
    }

    void clear_expected_certificate_identities()
    {
      expected_identities_.clear();
      logger_->debug("Cleared all expected certificate identities");
    }

    const std::vector<std::pair<std::string, std::string>> &get_expected_identities() const
    {
      return expected_identities_;
    }

  private:
    std::unique_ptr<TransparencyLogVerifier> transparency_log_verifier_;
    std::shared_ptr<spdlog::logger> logger_;
    std::shared_ptr<CertificateStore> certificate_store_;
    std::string rekor_public_key_;
    std::vector<std::pair<std::string, std::string>> expected_identities_;
  };

  SigstoreVerifier::SigstoreVerifier()
    : pimpl(std::make_unique<Impl>())
  {
  }

  SigstoreVerifier::~SigstoreVerifier() = default;
  SigstoreVerifier::SigstoreVerifier(SigstoreVerifier &&) noexcept = default;
  SigstoreVerifier &SigstoreVerifier::operator=(SigstoreVerifier &&) noexcept = default;

  outcome::std_result<void> SigstoreVerifier::verify_blob(std::string_view data, std::string_view bundle_json)
  {
    return pimpl->verify(data, bundle_json);
  }

  outcome::std_result<void> SigstoreVerifier::load_embedded_fulcio_ca_certificates()
  {
    return pimpl->load_embedded_fulcio_ca_certificates();
  }
  outcome::std_result<void> SigstoreVerifier::add_ca_certificate(const std::string &ca_certificate)
  {
    return pimpl->add_ca_certificates(ca_certificate);
  }

  void SigstoreVerifier::add_expected_identity(const std::string &email, const std::string &issuer)
  {
    pimpl->add_expected_identity(email, issuer);
  }

  void SigstoreVerifier::remove_expected_identity(const std::string &email, const std::string &issuer)
  {
    pimpl->remove_expected_identity(email, issuer);
  }

  void SigstoreVerifier::clear_expected_certificate_identities()
  {
    pimpl->clear_expected_certificate_identities();
  }
} // namespace sigstore
