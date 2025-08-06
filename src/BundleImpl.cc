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

#include "BundleImpl.hh"

#include <boost/json/serialize.hpp>

#include "BundleLoader.hh"
#include "CertificateStore.hh" // IWYU pragma: keep
#include "ContextImpl.hh"
#include "TransparencyLogVerifier.hh"
#include "sigstore/Errors.hh"
#include "sigstore_bundle.pb.h"

namespace sigstore
{
  BundleImpl::BundleImpl(std::shared_ptr<ContextImpl> context, dev::sigstore::bundle::v1::Bundle internal_bundle)
    : context_(std::move(context))
    , internal_bundle_(std::move(internal_bundle))
    , certificate_(extract_certificate())
  {
  }

  std::shared_ptr<BundleImpl> BundleImpl::create(std::shared_ptr<ContextImpl> context, const dev::sigstore::bundle::v1::Bundle &bundle)
  {
    return std::make_shared<BundleImpl>(context, bundle);
  }

  outcome::std_result<std::shared_ptr<Bundle>> BundleImpl::create(std::shared_ptr<ContextImpl> context, std::string_view bundle_json)
  {
    SigstoreBundleLoader loader;
    std::string bundle_str(bundle_json);
    auto bundle_result = loader.load_from_json(bundle_str);
    if (!bundle_result)
      {
        return bundle_result.error();
      }

    auto internal_bundle = bundle_result.value();
    auto bundle_impl = std::make_shared<BundleImpl>(context, std::move(internal_bundle));

    return std::static_pointer_cast<Bundle>(bundle_impl);
  }

  std::string BundleImpl::get_signature() const
  {
    return extract_signature();
  }

  std::shared_ptr<Certificate> BundleImpl::get_certificate() const
  {
    return certificate_;
  }

  std::shared_ptr<CertificateInfo> BundleImpl::get_certificate_info() const
  {
    return certificate_;
  }

  const dev::sigstore::bundle::v1::Bundle &BundleImpl::get_bundle() const
  {
    return internal_bundle_;
  }

  std::optional<std::string> BundleImpl::get_message_digest() const
  {
    return extract_message_digest();
  }

  std::optional<std::string> BundleImpl::get_algorithm() const
  {
    return extract_algorithm();
  }

  int64_t BundleImpl::get_log_index() const
  {
    return extract_log_index();
  }

  const ::google::protobuf::RepeatedPtrField<::dev::sigstore::rekor::v1::TransparencyLogEntry> &BundleImpl::get_transparency_log_entries() const
  {
    if (!internal_bundle_.has_verification_material())
      {
        static const ::google::protobuf::RepeatedPtrField<::dev::sigstore::rekor::v1::TransparencyLogEntry> empty_entries;
        return empty_entries;
      }

    return internal_bundle_.verification_material().tlog_entries();
  }

  std::shared_ptr<Certificate> BundleImpl::extract_certificate() const
  {
    if (!internal_bundle_.has_verification_material())
      {
        logger_->warn("Bundle has no verification material");
        return nullptr;
      }

    const auto &verification_material = internal_bundle_.verification_material();
    if (!verification_material.has_certificate())
      {
        logger_->warn("Bundle has no certificate");
        return nullptr;
      }

    const auto &cert_data = verification_material.certificate().raw_bytes();
    auto certificate = Certificate::from_der(cert_data);
    if (!certificate)
      {
        logger_->error("Failed to parse certificate from bundle");
        return nullptr;
      }

    return certificate;
  }

  std::string BundleImpl::extract_signature() const
  {
    if (!internal_bundle_.has_message_signature())
      {
        return "";
      }

    const auto &message_signature = internal_bundle_.message_signature();
    return message_signature.signature();
  }

  std::optional<std::string> BundleImpl::extract_message_digest() const
  {
    if (!internal_bundle_.has_message_signature())
      {
        return std::nullopt;
      }

    const auto &message_signature = internal_bundle_.message_signature();
    if (!message_signature.has_message_digest())
      {
        return std::nullopt;
      }

    const auto &message_digest = message_signature.message_digest();
    return message_digest.digest();
  }

  std::optional<std::string> BundleImpl::extract_algorithm() const
  {
    if (!internal_bundle_.has_message_signature())
      {
        return std::nullopt;
      }

    const auto &message_signature = internal_bundle_.message_signature();
    if (!message_signature.has_message_digest())
      {
        return std::nullopt;
      }

    const auto &message_digest = message_signature.message_digest();

    // Convert the enum to string
    switch (message_digest.algorithm())
      {
      case dev::sigstore::common::v1::HashAlgorithm::SHA2_256:
        return "sha256";
      case dev::sigstore::common::v1::HashAlgorithm::SHA2_384:
        return "sha384";
      case dev::sigstore::common::v1::HashAlgorithm::SHA2_512:
        return "sha512";
      case dev::sigstore::common::v1::HashAlgorithm::SHA3_256:
        return "sha3-256";
      case dev::sigstore::common::v1::HashAlgorithm::SHA3_384:
        return "sha3-384";
      default:
        logger_->warn("Unknown hash algorithm: {}", static_cast<int>(message_digest.algorithm()));
        return std::nullopt;
      }
  }

  int64_t BundleImpl::extract_log_index() const
  {
    if (!internal_bundle_.has_verification_material())
      {
        return -1;
      }

    const auto &verification_material = internal_bundle_.verification_material();
    if (verification_material.tlog_entries_size() == 0)
      {
        return -1;
      }

    const auto &entry = verification_material.tlog_entries(0);
    return entry.log_index();
  }

  outcome::std_result<void> BundleImpl::verify(const std::string_view &data)
  {
    auto verify_result = verify_signature(data);
    if (!verify_result)
      {
        logger_->error("Signature verification failed: {}", verify_result.error().message());
        return verify_result.error();
      }

    auto chain_result = verify_certificate_chain();
    if (!chain_result)
      {
        logger_->error("Certificate chain verification failed: {}", chain_result.error().message());
        return chain_result.error();
      }

    auto log_result = verify_transparency_log_offline();
    if (!log_result)
      {
        logger_->error("Transparency log verification failed: {}", log_result.error().message());
        return log_result.error();
      }

    return outcome::success();
  }

  outcome::std_result<void> BundleImpl::verify_signature(const std::string_view &data) const
  {
    auto certificate = get_certificate();
    const auto &signature = get_signature();

    std::vector<uint8_t> signature_bytes;
    signature_bytes.assign(signature.begin(), signature.end());

    std::vector<uint8_t> data_bytes(data.begin(), data.end());
    return certificate->verify_signature(data_bytes, signature_bytes);
  }

  outcome::std_result<void> BundleImpl::verify_certificate_chain() const
  {
    auto cert = get_certificate();
    return context_->get_certificate_store()->verify_certificate_chain(cert);
  }

  outcome::std_result<void> BundleImpl::verify_transparency_log_offline() const
  {
    auto tlog = get_transparency_log_entries();

    if (tlog.empty())
      {
        logger_->warn("No transparency log entries found in bundle");
        return SigstoreError::InvalidTransparencyLog;
      }

    TransparencyLogVerifier transparency_log_verifier;
    auto &entry = tlog[0];
    auto log_result = transparency_log_verifier.verify_transparency_log(entry, get_certificate());

    if (!log_result)
      {
        logger_->error("Transparency log verification failed: {}", log_result.error().message());
        return log_result.error();
      }

    return outcome::success();
  }

} // namespace sigstore
