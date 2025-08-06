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

#ifndef TRANSPARENCY_LOG_VERIFIER_HH
#define TRANSPARENCY_LOG_VERIFIER_HH

#include <memory>
#include <string>
#include <boost/json.hpp>
#include <boost/outcome/std_result.hpp>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include "CanonicalBodyParser.hh"
#include "Certificate.hh"
#include "Logging.hh"
#include "MerkleTreeValidator.hh"
#include "PublicKey.hh"
#include "RFC6962Hasher.hh"
#include "sigstore_bundle.pb.h"
#include "sigstore_rekor.pb.h"

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  class BundleImpl;
  class PublicKey;
  class MerkleTreeValidator;

  class TransparencyLogVerifier
  {
  public:
    TransparencyLogVerifier();
    ~TransparencyLogVerifier();

    TransparencyLogVerifier(const TransparencyLogVerifier &) = delete;
    TransparencyLogVerifier &operator=(const TransparencyLogVerifier &) = delete;
    TransparencyLogVerifier(TransparencyLogVerifier &&) noexcept = default;
    TransparencyLogVerifier &operator=(TransparencyLogVerifier &&) noexcept = default;

    outcome::std_result<void> verify_transparency_log(dev::sigstore::rekor::v1::TransparencyLogEntry entry, std::shared_ptr<Certificate> certificate);
    outcome::std_result<void> verify_bundle_consistency(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry,
                                                        std::shared_ptr<BundleImpl> bundle);

  private:
    outcome::std_result<void> verify_inclusion_proof(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry);
    outcome::std_result<void> verify_checkpoint(const dev::sigstore::rekor::v1::Checkpoint &checkpoint,
                                                const std::string &expected_root_hash,
                                                int64_t expected_tree_size);
    outcome::std_result<void> verify_signed_entry_timestamp(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry);
    outcome::std_result<void> verify_integrated_time(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry,
                                                     std::shared_ptr<Certificate> certificate);
    outcome::std_result<void> verify_rekor_log_entry_signature(const std::string &log_entry, const std::string &signature_b64);

    outcome::std_result<void> verify_signature_consistency(const HashedRekord &rekord, std::shared_ptr<BundleImpl> bundle);
    outcome::std_result<void> verify_certificate_consistency(const HashedRekord &rekord, std::shared_ptr<Certificate> bundle_certificate);
    outcome::std_result<void> verify_hash_consistency(const HashedRekord &rekord, std::shared_ptr<BundleImpl> bundle);

    std::string compute_leaf_hash(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry);
    outcome::std_result<void> load_embedded_certificates();

  private:
    std::shared_ptr<spdlog::logger> logger_{Logging::create("sigstore:transparency_log_verifier")};
    RFC6962Hasher hasher_;
    std::shared_ptr<PublicKey> rekor_public_key_;
    std::unique_ptr<MerkleTreeValidator> merkle_validator_;
  };

} // namespace sigstore

#endif // TRANSPARENCY_LOG_VERIFIER_HH
