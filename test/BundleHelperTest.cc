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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>

#include "BundleHelper.hh"
#include "BundleLoader.hh"
#include "sigstore_bundle.pb.h"
#include "TestUtils.hh"

namespace sigstore::test
{

  class BundleHelperTest : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      // Load a real bundle for most tests to avoid protobuf setup issues
      SigstoreBundleLoader loader;
      auto result = loader.load_from_file(find_test_data_file("appcast-sigstore.xml.sigstore.bundle"));
      ASSERT_TRUE(result.has_value()) << "Failed to load test bundle file";
      real_bundle_ = result.value();
    }

    void TearDown() override
    {
    }

    // Test constants
    static constexpr int64_t EXPECTED_LOG_INDEX = 270584577;
    static constexpr int64_t SECOND_LOG_INDEX = 270584578;
    static constexpr int UNKNOWN_ALGORITHM = 999;

    dev::sigstore::bundle::v1::Bundle real_bundle_;
  };

  TEST_F(BundleHelperTest, Constructor_ValidBundle)
  {
    EXPECT_NO_THROW({ BundleHelper helper(real_bundle_); });
  }

  TEST_F(BundleHelperTest, GetSignature_ValidBundle)
  {
    BundleHelper helper(real_bundle_);
    std::string signature = helper.get_signature();

    // Verify signature is not empty and has expected binary length (DER-encoded ECDSA signature)
    EXPECT_FALSE(signature.empty());
    EXPECT_GT(signature.length(), 60); // Typical ECDSA signature is 70-72 bytes
    EXPECT_LT(signature.length(), 80);
  }

  TEST_F(BundleHelperTest, GetSignature_NoMessageSignature)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");

    BundleHelper helper(bundle);
    std::string signature = helper.get_signature();
    EXPECT_EQ(signature, "");
  }

  TEST_F(BundleHelperTest, GetCertificate_ValidBundle)
  {
    BundleHelper helper(real_bundle_);
    auto certificate = helper.get_certificate();
    EXPECT_NE(certificate, nullptr);
  }

  TEST_F(BundleHelperTest, GetCertificate_NoVerificationMaterial)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");

    BundleHelper helper(bundle);
    auto certificate = helper.get_certificate();
    EXPECT_EQ(certificate, nullptr);
  }

  TEST_F(BundleHelperTest, GetCertificate_CorruptedCertificateData)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");

    // Create verification material with corrupted certificate data
    auto *verification_material = bundle.mutable_verification_material();
    auto *certificate = verification_material->mutable_certificate();

    // Set invalid DER data that will cause Certificate::from_der to fail
    std::string corrupted_der = "invalid_der_data_that_will_fail_parsing";
    certificate->set_raw_bytes(corrupted_der);

    BundleHelper helper(bundle);
    auto cert_result = helper.get_certificate();
    EXPECT_EQ(cert_result, nullptr);
  }

  TEST_F(BundleHelperTest, GetMessageDigest_ValidBundle)
  {
    BundleHelper helper(real_bundle_);
    auto digest = helper.get_message_digest();
    EXPECT_TRUE(digest.has_value());

    // Verify digest is not empty and has expected binary length (SHA256 is 32 bytes)
    EXPECT_FALSE(digest.value().empty());
    EXPECT_EQ(digest.value().length(), 32); // SHA256 digest is 32 bytes
  }

  TEST_F(BundleHelperTest, GetMessageDigest_NoMessageSignature)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");

    BundleHelper helper(bundle);
    auto digest = helper.get_message_digest();
    EXPECT_FALSE(digest.has_value());
  }

  TEST_F(BundleHelperTest, GetAlgorithm_SHA256_ValidBundle)
  {
    BundleHelper helper(real_bundle_);
    auto algorithm = helper.get_algorithm();
    EXPECT_TRUE(algorithm.has_value());
    EXPECT_EQ(algorithm.value(), "sha256");
  }

  TEST_F(BundleHelperTest, GetAlgorithm_AllSupportedAlgorithms)
  {
    struct AlgorithmTest
    {
      dev::sigstore::common::v1::HashAlgorithm algo;
      std::string expected;
    };

    std::vector<AlgorithmTest> tests = {{dev::sigstore::common::v1::HashAlgorithm::SHA2_256, "sha256"},
                                        {dev::sigstore::common::v1::HashAlgorithm::SHA2_384, "sha384"},
                                        {dev::sigstore::common::v1::HashAlgorithm::SHA2_512, "sha512"},
                                        {dev::sigstore::common::v1::HashAlgorithm::SHA3_256, "sha3-256"},
                                        {dev::sigstore::common::v1::HashAlgorithm::SHA3_384, "sha3-384"}};

    for (const auto &test: tests)
      {
        dev::sigstore::bundle::v1::Bundle bundle;
        bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");
        auto *message_signature = bundle.mutable_message_signature();
        message_signature->set_signature("test_signature");
        auto *message_digest = message_signature->mutable_message_digest();
        message_digest->set_algorithm(test.algo);
        message_digest->set_digest("test_digest");

        BundleHelper helper(bundle);
        auto algorithm = helper.get_algorithm();
        EXPECT_TRUE(algorithm.has_value()) << "Algorithm should be recognized: " << test.expected;
        if (algorithm.has_value())
          {
            EXPECT_EQ(algorithm.value(), test.expected) << "Algorithm mismatch for " << test.expected;
          }
      }
  }

  TEST_F(BundleHelperTest, GetAlgorithm_UnknownAlgorithm)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");
    auto *message_signature = bundle.mutable_message_signature();
    message_signature->set_signature("test_signature");
    auto *message_digest = message_signature->mutable_message_digest();
    // Set an unknown/unsupported algorithm (using cast to set invalid enum value)
    message_digest->set_algorithm(static_cast<dev::sigstore::common::v1::HashAlgorithm>(UNKNOWN_ALGORITHM));
    message_digest->set_digest("test_digest");

    BundleHelper helper(bundle);
    auto algorithm = helper.get_algorithm();
    EXPECT_FALSE(algorithm.has_value());
  }

  TEST_F(BundleHelperTest, GetAlgorithm_NoMessageSignature)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");

    BundleHelper helper(bundle);
    auto algorithm = helper.get_algorithm();
    EXPECT_FALSE(algorithm.has_value());
  }

  TEST_F(BundleHelperTest, GetLogIndex_ValidBundle)
  {
    BundleHelper helper(real_bundle_);
    int64_t log_index = helper.get_log_index();
    EXPECT_EQ(log_index, EXPECTED_LOG_INDEX);
  }

  TEST_F(BundleHelperTest, GetLogIndex_NoVerificationMaterial)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");

    BundleHelper helper(bundle);
    int64_t log_index = helper.get_log_index();
    EXPECT_EQ(log_index, -1);
  }

  TEST_F(BundleHelperTest, GetTransparencyLogEntries_ValidBundle)
  {
    BundleHelper helper(real_bundle_);
    const auto &entries = helper.get_transparency_log_entries();
    EXPECT_EQ(entries.size(), 1);
    EXPECT_EQ(entries[0].log_index(), EXPECTED_LOG_INDEX);
  }

  TEST_F(BundleHelperTest, GetTransparencyLogEntries_EmptyBundle)
  {
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");

    BundleHelper helper(bundle);
    const auto &entries = helper.get_transparency_log_entries();
    EXPECT_EQ(entries.size(), 0);
  }

  TEST_F(BundleHelperTest, GetTransparencyLogEntries_MultipleEntries)
  {
    // Create a bundle with multiple entries to test the path where we return multiple entries
    dev::sigstore::bundle::v1::Bundle bundle;
    bundle.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");
    auto *verification_material = bundle.mutable_verification_material();

    auto *tlog_entry1 = verification_material->add_tlog_entries();
    tlog_entry1->set_log_index(EXPECTED_LOG_INDEX);

    auto *tlog_entry2 = verification_material->add_tlog_entries();
    tlog_entry2->set_log_index(SECOND_LOG_INDEX);

    BundleHelper helper(bundle);
    const auto &entries = helper.get_transparency_log_entries();
    EXPECT_EQ(entries.size(), 2);
    EXPECT_EQ(entries[0].log_index(), EXPECTED_LOG_INDEX);
    EXPECT_EQ(entries[1].log_index(), SECOND_LOG_INDEX);
  }

  // Test cases to cover edge cases in extract methods
  TEST_F(BundleHelperTest, ExtractMethods_EdgeCases)
  {
    // Test case where bundle has message signature but no message digest
    dev::sigstore::bundle::v1::Bundle bundle_no_digest;
    bundle_no_digest.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");
    auto *message_signature = bundle_no_digest.mutable_message_signature();
    message_signature->set_signature("test_signature");
    // Don't set message_digest

    BundleHelper helper_no_digest(bundle_no_digest);
    EXPECT_FALSE(helper_no_digest.get_message_digest().has_value());
    EXPECT_FALSE(helper_no_digest.get_algorithm().has_value());

    // Test case where bundle has verification material but no tlog entries
    dev::sigstore::bundle::v1::Bundle bundle_no_tlog;
    bundle_no_tlog.set_media_type("application/vnd.dev.sigstore.bundle.v0.3+json");
    auto *verification_material = bundle_no_tlog.mutable_verification_material();
    (void)verification_material; // Suppress unused warning
    // Don't add any tlog entries

    BundleHelper helper_no_tlog(bundle_no_tlog);
    EXPECT_EQ(helper_no_tlog.get_log_index(), -1);
  }

  // Test all public methods work with the real bundle to ensure integration
  TEST_F(BundleHelperTest, AllMethodsWithRealBundle)
  {
    BundleHelper helper(real_bundle_);

    // Test all methods work with real data
    std::string signature = helper.get_signature();
    EXPECT_FALSE(signature.empty());

    auto certificate = helper.get_certificate();
    EXPECT_NE(certificate, nullptr);

    auto digest = helper.get_message_digest();
    EXPECT_TRUE(digest.has_value());

    auto algorithm = helper.get_algorithm();
    EXPECT_TRUE(algorithm.has_value());
    EXPECT_EQ(algorithm.value(), "sha256");

    int64_t log_index = helper.get_log_index();
    EXPECT_GT(log_index, 0);

    const auto &entries = helper.get_transparency_log_entries();
    EXPECT_GT(entries.size(), 0);
  }

} // namespace sigstore::test
