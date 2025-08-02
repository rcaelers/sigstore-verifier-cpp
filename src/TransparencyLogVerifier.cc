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

#include "TransparencyLogVerifier.hh"

#include <fmt/format.h>
#include <algorithm>
#include <memory>
#include <cctype>
#include <boost/json.hpp>
#include <openssl/evp.h>
#include <fmt/chrono.h>

#include "BundleHelper.hh"
#include "Base64.hh"
#include "Certificate.hh"
#include "PublicKey.hh"
#include "MerkleTreeValidator.hh"
#include "CheckpointParser.hh"
#include "CanonicalBodyParser.hh"

#include "sigstore/SigstoreErrors.hh"

#include "sigstore_rekor.pb.h"
#include "embedded_rekor_pubkey.h"

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  TransparencyLogVerifier::TransparencyLogVerifier(VerificationConfig config)
    : config_(std::move(config))
  {
    merkle_validator_ = std::make_unique<MerkleTreeValidator>();

    [[maybe_unused]] auto result = load_embedded_certificates();
  }

  TransparencyLogVerifier::~TransparencyLogVerifier() = default;

  outcome::std_result<void> TransparencyLogVerifier::load_embedded_certificates()
  {
    // Use the embedded rekor public key from generated header
    std::string rekor_pem{embedded_rekor_pubkey};

    auto public_key = PublicKey::from_pem(rekor_pem);
    if (!public_key)
      {
        logger_->error("Failed to parse embedded Rekor public key");
        return SigstoreError::InvalidCertificate;
      }

    rekor_public_key_ = public_key;
    logger_->info("Loaded embedded Rekor public key successfully (type {})", rekor_public_key_->get_algorithm_name());
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_transparency_log(dev::sigstore::rekor::v1::TransparencyLogEntry entry,
                                                                            std::shared_ptr<Certificate> certificate,
                                                                            const std::vector<std::pair<std::string, std::string>> &expected_identities)
  {
    logger_->debug("Verifying transparency log entry with log index: {}", entry.log_index());

    auto inclusion_valid = verify_inclusion_proof(entry);
    if (!inclusion_valid)
      {
        return inclusion_valid.error();
      }

    auto timestamp_valid = verify_signed_entry_timestamp(entry);
    if (!timestamp_valid)
      {
        return timestamp_valid.error();
      }

    auto integrated_time_valid = verify_integrated_time(entry, certificate);
    if (!integrated_time_valid)
      {
        return integrated_time_valid.error();
      }

    auto extensions_valid = verify_certificate_extensions(certificate, expected_identities);
    if (!extensions_valid)
      {
        return extensions_valid.error();
      }

    auto key_usage_valid = certificate->verify_key_usage();
    if (!key_usage_valid)
      {
        return key_usage_valid.error();
      }
    logger_->debug("Certificate key usage validation successful");
    return outcome::success();
  }

  // =============================================================================
  // Inclusion Proof
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_inclusion_proof(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry)
  {
    if (!entry.has_inclusion_proof())
      {
        logger_->error("No inclusion proof provided for transparency log entry");
        return SigstoreError::InvalidTransparencyLog;
      }

    const dev::sigstore::rekor::v1::InclusionProof &proof = entry.inclusion_proof();

    if (!proof.has_checkpoint())
      {
        logger_->error("No checkpoint provided in inclusion proof");
        return SigstoreError::InvalidTransparencyLog;
      }

    std::string leaf_hash = compute_leaf_hash(entry);
    if (leaf_hash.empty())
      {
        logger_->error("Failed to compute leaf hash for inclusion proof verification");
        return SigstoreError::InvalidTransparencyLog;
      }

    auto inclusion_valid = merkle_validator_->verify_inclusion_proof(proof.hashes(),
                                                                     proof.log_index(),
                                                                     proof.tree_size(),
                                                                     leaf_hash,
                                                                     proof.root_hash());
    if (!inclusion_valid)
      {
        return inclusion_valid.error();
      }

    auto checkpoint_valid = verify_checkpoint(proof.checkpoint(), proof.root_hash(), proof.tree_size());
    if (!checkpoint_valid)
      {
        return checkpoint_valid.error();
      }
    return outcome::success();
  }

  std::string TransparencyLogVerifier::compute_leaf_hash(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry)
  {
    try
      {
        if (entry.canonicalized_body().empty())
          {
            logger_->error("Cannot compute leaf hash without body data");
            return "";
          }

        return hasher_.hash_leaf(entry.canonicalized_body());
      }
    catch (const std::exception &e)
      {
        logger_->error("Error computing leaf hash: {}", e.what());
        return "";
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_checkpoint(const dev::sigstore::rekor::v1::Checkpoint &checkpoint,
                                                                       const std::string &expected_root_hash,
                                                                       int64_t expected_tree_size)
  {
    logger_->debug("Verifying checkpoint using CheckpointParser");

    // Use CheckpointParser to parse the checkpoint from protobuf
    CheckpointParser parser;
    auto parsed_result = parser.parse_from_protobuf(checkpoint);
    if (!parsed_result)
      {
        logger_->error("Failed to parse checkpoint from protobuf: {}", parsed_result.error().message());
        return parsed_result.error();
      }
    const auto &parsed_checkpoint = parsed_result.value();
    auto expected_root_hash_b64_result = Base64::encode(expected_root_hash);
    if (!expected_root_hash_b64_result.has_value())
      {
        logger_->error("Failed to encode expected root hash to Base64: {}", expected_root_hash_b64_result.error().message());
        return expected_root_hash_b64_result.error();
      }
    const auto &expected_root_hash_b64 = expected_root_hash_b64_result.value();

    // Verify basic checkpoint fields
    if (parsed_checkpoint.origin.empty())
      {
        logger_->error("Checkpoint origin is empty");
        return SigstoreError::InvalidTransparencyLog;
      }
    if (static_cast<int64_t>(parsed_checkpoint.tree_size) != expected_tree_size)
      {
        logger_->error("Checkpoint tree size {} does not match expected tree size {}", parsed_checkpoint.tree_size, expected_tree_size);
        return SigstoreError::InvalidTransparencyLog;
      }
    if (parsed_checkpoint.root_hash != expected_root_hash_b64)
      {
        logger_->error("Checkpoint root hash {} does not match expected root hash {}", parsed_checkpoint.root_hash, expected_root_hash_b64);
        return SigstoreError::InvalidTransparencyLog;
      }

    // Verify checkpoint signatures
    if (parsed_checkpoint.signatures.empty())
      {
        logger_->error("No signatures found in checkpoint");
        return SigstoreError::InvalidTransparencyLog;
      }

    // Verify signatures using the checkpoint body
    for (const auto &sig: parsed_checkpoint.signatures)
      {
        if (sig.signer.starts_with("rekor.sigstore.dev"))
          {
            logger_->debug("Verifying checkpoint signature for signer: {}", sig.signer);
            auto valid = verify_rekor_log_entry_signature(parsed_checkpoint.body, sig.signature);
            if (!valid)
              {
                return valid.error();
              }
          }
        else
          {
            logger_->warn("Skipping checkpoint signature verification for unknown signer: {}", sig.signer);
          }
      }

    logger_->debug("Checkpoint verification successful");
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_rekor_log_entry_signature(const std::string &log_entry, const std::string &signature_b64)
  {
    if (!rekor_public_key_)
      {
        logger_->error("Rekor public key is not loaded, cannot verify transparency log entry");
        return SigstoreError::InvalidTransparencyLog;
      }

    try
      {
        auto signature_data_result = Base64::decode(signature_b64);
        if (!signature_data_result.has_value())
          {
            logger_->error("Failed to decode Base64 signature: {}", signature_data_result.error().message());
            return signature_data_result.error();
          }
        std::string signature_data = signature_data_result.value();

        // Remove first 4 bytes (key hint)
        if (signature_data.size() > 4)
          {
            signature_data = signature_data.substr(4);
          }
        else
          {
            logger_->error("Signature data too short to remove header bytes");
            return SigstoreError::InvalidTransparencyLog;
          }

        auto verify_result = rekor_public_key_->verify_signature(log_entry, signature_data);
        if (!verify_result)
          {
            logger_->error("Rekor log entry signature verification failed: {}", verify_result.error().message());
            return SigstoreError::InvalidTransparencyLog;
          }

        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception during signature verification: {}", e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  // =============================================================================
  // Signed Entry Timestamp
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_signed_entry_timestamp(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry)
  {
    logger_->debug("Verifying signed entry timestamp");
    if (!entry.has_inclusion_promise())
      {
        logger_->error("No inclusion promise to verify");
        return SigstoreError::InvalidTransparencyLog;
      }
    const dev::sigstore::rekor::v1::InclusionPromise &promise = entry.inclusion_promise();

    std::string signature_data = promise.signed_entry_timestamp();
    if (signature_data.empty())
      {
        logger_->error("Failed to decode signed entry timestamp");
        return SigstoreError::InvalidTransparencyLog;
      }

    if (entry.canonicalized_body().empty())
      {
        logger_->error("Cannot verify signed entry timestamp without body data");
        return SigstoreError::InvalidTransparencyLog;
      }

    std::string log_id;
    std::string key_id_binary = entry.log_id().key_id();

    std::stringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (unsigned char byte: key_id_binary)
      {
        hex_stream << std::setw(2) << static_cast<unsigned int>(byte);
      }
    log_id = hex_stream.str();

    auto canonicalized_body_b64_result = Base64::encode(entry.canonicalized_body());
    if (!canonicalized_body_b64_result.has_value())
      {
        logger_->error("Failed to encode canonicalized body to Base64: {}", canonicalized_body_b64_result.error().message());
        return canonicalized_body_b64_result.error();
      }

    auto canonicalized_payload = fmt::format(R"({{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}})",
                                             canonicalized_body_b64_result.value(),
                                             entry.integrated_time(),
                                             log_id,
                                             entry.log_index());

    spdlog::debug("Canonicalized payload for signed entry timestamp verification: {}", canonicalized_payload);
    auto verify_result = rekor_public_key_->verify_signature(canonicalized_payload, signature_data);
    if (!verify_result)
      {
        logger_->warn("Signed entry timestamp verification failed: {}", verify_result.error().message());
        return SigstoreError::InvalidTransparencyLog;
      }

    return outcome::success();
  }

  // =============================================================================
  // Integrated Time
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_integrated_time(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry,
                                                                            std::shared_ptr<Certificate> certificate)
  {
    int64_t integrated_time_seconds = entry.integrated_time();
    auto integrated_time = std::chrono::system_clock::from_time_t(static_cast<std::time_t>(integrated_time_seconds));
    logger_->debug("Verifying integrated time: {}", integrated_time);

    auto cert_valid_at_time_result = certificate->is_valid_at_time(integrated_time);
    if (!cert_valid_at_time_result)
      {
        return cert_valid_at_time_result.error();
      }
    if (!cert_valid_at_time_result.value())
      {
        logger_->error("Certificate validity check failed at integrated time: {}", integrated_time_seconds);
        return SigstoreError::InvalidTransparencyLog;
      }

    auto current_time = std::chrono::system_clock::now();
    constexpr auto MAX_CLOCK_SKEW = std::chrono::seconds(300); // 5 minutes

    if (integrated_time > current_time + MAX_CLOCK_SKEW)
      {
        logger_->warn("Integrated time {} is too far in the future (current: {})",
                      integrated_time_seconds,
                      std::chrono::system_clock::to_time_t(current_time));
        return SigstoreError::InvalidCertificate;
      }

    logger_->debug("Integrated time validation successful: certificate was valid at {}", integrated_time_seconds);
    return outcome::success();
  }

  // =============================================================================
  // Certificates
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_certificate_extensions(const std::shared_ptr<Certificate> &certificate,
                                                                                   const std::vector<std::pair<std::string, std::string>> &expected_identities)
  {
    try
      {
        logger_->debug("Verifying certificate extensions");

        // Verify Subject Alternative Name (email)
        std::string subject_email = certificate->subject_email();
        if (subject_email.empty())
          {
            logger_->error("Certificate does not contain a subject email in SAN extension");
            return SigstoreError::InvalidCertificate;
          }
        logger_->debug("Found subject email: {}", subject_email);

        // Verify OIDC issuer extension
        std::string oidc_issuer = certificate->oidc_issuer();
        if (oidc_issuer.empty())
          {
            logger_->error("Certificate does not contain OIDC issuer extension");
            return SigstoreError::InvalidCertificate;
          }
        logger_->debug("Found OIDC issuer: {}", oidc_issuer);

        // If expected identities are provided, validate against them
        if (!expected_identities.empty())
          {
            bool identity_match_found = false;
            for (const auto &[expected_email, expected_issuer] : expected_identities)
              {
                if (subject_email == expected_email && oidc_issuer == expected_issuer)
                  {
                    identity_match_found = true;
                    logger_->debug("Certificate identity matches expected: email='{}', issuer='{}'", expected_email, expected_issuer);
                    break;
                  }
              }

            if (!identity_match_found)
              {
                logger_->error("Certificate identity does not match any expected identities: email='{}', issuer='{}'", subject_email, oidc_issuer);
                return SigstoreError::InvalidCertificate;
              }
          }

        // Validate that the OIDC issuer is from a trusted source (e.g., GitHub, GitLab, etc.)
        const std::vector<std::string> trusted_issuers = {"https://github.com/login/oauth",
                                                          "https://gitlab.com",
                                                          "https://accounts.google.com",
                                                          "https://oauth2.sigstore.dev/auth"};

        bool issuer_trusted = std::ranges::find(trusted_issuers, oidc_issuer) != trusted_issuers.end();
        if (!issuer_trusted)
          {
            logger_->warn("OIDC issuer '{}' is not in the list of trusted issuers", oidc_issuer);
          }

        logger_->debug("Certificate extensions validation successful");
        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during certificate extensions verification: {}", e.what());
        return SigstoreError::InvalidCertificate;
      }
  }

  // =============================================================================
  // Bundle Consistency Verification
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_bundle_consistency(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry,
                                                                               const dev::sigstore::bundle::v1::Bundle &bundle)
  {
    try
      {
        logger_->debug("Verifying bundle consistency with transparency log entry");

        if (entry.canonicalized_body().empty())
          {
            logger_->error("Cannot verify bundle consistency without body data");
            return SigstoreError::InvalidTransparencyLog;
          }
        if (!bundle.has_verification_material())
          {
            logger_->error("Bundle does not contain verification material");
            return SigstoreError::InvalidTransparencyLog;
          }
        if (!bundle.has_message_signature())
          {
            logger_->error("Bundle does not contain message signature");
            return SigstoreError::InvalidTransparencyLog;
          }

        CanonicalBodyParser body_parser;
        auto body_parse_result = body_parser.parse_from_json(entry.canonicalized_body());
        if (!body_parse_result)
          {
            logger_->error("Failed to parse canonicalized body: {}", body_parse_result.error().message());
            return body_parse_result.error();
          }
        const auto &body_entry = body_parse_result.value();

        return std::visit(
          [bundle, body_entry, entry, this](auto &&spec) -> outcome::std_result<void> {
            using T = std::decay_t<decltype(spec)>;

            BundleHelper bundle_helper(bundle);
            auto bundle_certificate = bundle_helper.get_certificate();
            auto bundle_message_digest_opt = bundle_helper.get_message_digest();

            if (body_entry.kind != entry.kind_version().kind())
              {
                logger_->error("Bundle kind '{}' does not match canonicalized body kind '{}'", entry.kind_version().kind(), body_entry.kind);
                return SigstoreError::InvalidTransparencyLog;
              }
            if (body_entry.api_version != entry.kind_version().version())
              {
                logger_->error("Bundle API version '{}' does not match canonicalized body version '{}'",
                               entry.kind_version().version(),
                               body_entry.api_version);
                return SigstoreError::InvalidTransparencyLog;
              }

            if constexpr (std::is_same_v<T, HashedRekord>)
              {
                auto signature_valid = verify_signature_consistency(spec, bundle_helper);
                auto certificate_valid = verify_certificate_consistency(spec, bundle_certificate);
                auto hash_valid = bundle_message_digest_opt.has_value() ? verify_hash_consistency(spec, bundle_helper) : outcome::success();
                if (signature_valid && certificate_valid && hash_valid)
                  {
                    logger_->debug("Bundle consistency verification successful");
                    return outcome::success();
                  }
                return SigstoreError::InvalidTransparencyLog;
              }
            else
              {
                logger_->error("Unsupported transparency log entry type for bundle consistency verification");
                return SigstoreError::InvalidTransparencyLog;
              }
          },
          body_entry.spec);
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during bundle consistency verification: {}", e.what());
        return SigstoreError::SystemError;
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_signature_consistency(const HashedRekord &rekord, const BundleHelper &bundle_helper)
  {
    if (rekord.signature != bundle_helper.get_signature())
      {
        logger_->error("Signature mismatch between bundle and transparency log");
        logger_->debug("Bundle signature: {}", bundle_helper.get_signature());
        logger_->debug("TLog signature:  {}", rekord.signature);
        return SigstoreError::InvalidTransparencyLog;
      }

    logger_->debug("Signature consistency verified");
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_certificate_consistency(const HashedRekord &rekord, const std::shared_ptr<Certificate> bundle_certificate)
  {
    std::string tlog_certificate_pem = rekord.public_key;

    auto tlog_cert = Certificate::from_pem(tlog_certificate_pem);
    if (!tlog_cert)
      {
        logger_->error("Failed to parse transparency log certificate from PEM");
        return SigstoreError::InvalidTransparencyLog;
      }

    if (*bundle_certificate != *tlog_cert)
      {
        logger_->error("Certificate mismatch between bundle and transparency log");
        return SigstoreError::InvalidTransparencyLog;
      }

    logger_->debug("Certificate consistency verified");
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_hash_consistency(const HashedRekord &rekord, const BundleHelper &bundle_helper)
  {
    std::string tlog_hash_hex = rekord.hash_value;

    std::string tlog_hash_binary;
    constexpr int HEX_BASE = 16;
    for (size_t i = 0; i < tlog_hash_hex.length(); i += 2)
      {
        std::string byte_str = tlog_hash_hex.substr(i, 2);
        auto byte = static_cast<unsigned char>(std::stoul(byte_str, nullptr, HEX_BASE));
        tlog_hash_binary.push_back(static_cast<char>(byte));
      }

    if (bundle_helper.get_message_digest().has_value() && bundle_helper.get_message_digest().value() != tlog_hash_binary)
      {
        logger_->error("Hash mismatch between bundle and transparency log");

        auto bundle_hash_b64_result = Base64::encode(bundle_helper.get_message_digest().value());
        auto tlog_hash_b64_result = Base64::encode(tlog_hash_binary);

        if (bundle_hash_b64_result.has_value())
          {
            logger_->debug("Bundle hash: {}", bundle_hash_b64_result.value());
          }
        else
          {
            logger_->debug("Bundle hash: <failed to encode>");
          }

        if (tlog_hash_b64_result.has_value())
          {
            logger_->debug("TLog hash:   {}", tlog_hash_b64_result.value());
          }
        else
          {
            logger_->debug("TLog hash:   <failed to encode>");
          }
        return SigstoreError::InvalidTransparencyLog;
      }

    if (bundle_helper.get_algorithm().has_value() && bundle_helper.get_algorithm().value() != rekord.hash_algorithm)
      {
        logger_->error("Hash algorithm mismatch between bundle and transparency log");
        logger_->debug("Bundle hash algorithm: {}", bundle_helper.get_algorithm().value());
        logger_->debug("TLog hash algorithm:   {}", rekord.hash_algorithm);
        return SigstoreError::InvalidTransparencyLog;
      }
    logger_->debug("Hash consistency verified");
    return outcome::success();
  }

} // namespace sigstore
