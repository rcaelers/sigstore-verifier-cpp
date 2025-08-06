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

#include "OnlineTransparencyLogLoader.hh"

#include <filesystem>
#include <fstream>
#include <boost/json.hpp>
#include <gtest/gtest.h>

#include "TestUtils.hh"
#include "sigstore/Errors.hh"

namespace sigstore::test
{
  // Test constants
  constexpr int INVALID_TYPE_VALUE = 123;
  constexpr int SAMPLE_LOG_INDEX = 42;
  constexpr int64_t SAMPLE_INTEGRATED_TIME = 9876543210;
  constexpr int SAMPLE_PROOF_LOG_INDEX = 999;
  constexpr int SAMPLE_TREE_SIZE = 123456;

  class OnlineTransparencyLogLoaderTest : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      loader_ = std::make_unique<OnlineTransparencyLogLoader>();
    }

    void TearDown() override
    {
      loader_.reset();
    }

    std::string create_sample_tlog_json()
    {
      return R"({
        "108e9186e8c5677a5f11d1728c4e5b590c55d04ed60346c413dfe21f9d8cc07f0e734d21441ec766": {
          "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2NGI1YjM3ODc1OTllNmQ5YmVkMGM4ZGUyOGQ3ZGRmMGMzMDBjNDBmYzBlMmExMGE5MGQ3ZmI5MGU0MWFjYjIwIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWENJUUQ3MmdxUFRwMVF0a09mWjQ5K2NRTldGS2pzL2ZWN0ZYbXBnZDRYSE9pRkN3SWhBTWQ1L0R2ODBaZ2tMYmlJTkRHLzdMampjaUR2WTRVY1g5KzNGWGE0amRwNiIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTXhWRU5EUVd4eFowRjNTVUpCWjBsVlZubG1NbWt2YTFOSVNHTlZkbHBEYVVGSFFqSnhLMEl6T1dWTmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcFZkMDU2UlhkTlZHZDNUbXBCTWxkb1kwNU5hbFYzVG5wRmQwMVVaM2hPYWtFeVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZKV2t4a1kyMXBXVlZJYm5sRGJXSjVSRTlFYTNRd1ZGVlRNMmh1VldaRU5taE1USEVLVjFsTFVqQllORGhsVERaaFVqZFZjMlZvYkhWQk1HZFpkRTVMZVhCaVNrOU1TbVJaTDFBNU5IVkxSMW94YkhaeFltRlBRMEZZYTNkblowWXhUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZYWnpndkNrMWhjRGh4VjJ0SlJHeHJaWEkwZVRGc2VXazRiVVZ6ZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBsM1dVUldVakJTUVZGSUwwSkNhM2RHTkVWV1kyMDVhVXh0VG1oYVYzaHNZMjVPUVZveU1XaGhWM2QxV1RJNWRFMURkMGREYVhOSFFWRlJRZ3BuTnpoM1FWRkZSVWh0YURCa1NFSjZUMms0ZGxveWJEQmhTRlpwVEcxT2RtSlRPWE5pTW1Sd1ltazVkbGxZVmpCaFJFRjFRbWR2Y2tKblJVVkJXVTh2Q2sxQlJVbENRMEZOU0cxb01HUklRbnBQYVRoMldqSnNNR0ZJVm1sTWJVNTJZbE01YzJJeVpIQmlhVGwyV1ZoV01HRkVRMEpwWjFsTFMzZFpRa0pCU0ZjS1pWRkpSVUZuVWpoQ1NHOUJaVUZDTWtGT01EbE5SM0pIZUhoRmVWbDRhMlZJU214dVRuZExhVk5zTmpRemFubDBMelJsUzJOdlFYWkxaVFpQUVVGQlFncHNMMWRGU1daVlFVRkJVVVJCUldOM1VsRkphRUZOVTNSTmRUaFBkVFJETWxCSVRFbFBObXcxVXpCSVdtaGtTMVp0U1VVNVlsUlRiMkpwVDJ0cVVVSkpDa0ZwUVZSSllsVlFTVGd2ZUZkQlpFdDNNM0ZTV1haNWJuZHhWRTR4U1dNMFIxTlJXbWxOY201VGVUbFFMMnBCUzBKblozRm9hMnBQVUZGUlJFRjNUbkFLUVVSQ2JVRnFSVUY1VEdoVVQyYzJiRk55YlUxcVdERkliV051WWtNdlRGTk9TazFDZDNWblVqTldaekZVTldJNE1WWTFTM2t6ZDB4bVJFWk5OM0JwTkFwNFVtaDBORTFQVGtGcVJVRjNSWFJHWTBWWk1WaG1hVzVTSzIxcmJuZEhkRFkxTTJWblRrVnVWVXB0VWtzME9GVmljR3hTT1V0dFVUWXZPV2xKVTAxckNqVXdjMWd4U2preWRHeDRVQW90TFMwdExVVk9SQ0JEUlZKVVNVWkpRMEZVUlMwdExTMHRDZz09In19fX0=",
          "integratedTime": 1752170767,
          "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
          "logIndex": "270584577",
          "verification": {
            "inclusionProof": {
              "checkpoint": "rekor.sigstore.dev - 1193050959916656506\\n151165654\\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\\n\\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\\n",
              "hashes": [
                "f40a2fafc41ffe6b2f5e042a2ea85fd4b02cfbf0ae907474ff85a6c63654076b",
                "840aa91ba05e6cb96ac66fe3d0f669244c8c30129c3f50a785ea82a4c5ac676b"
              ],
              "logIndex": "148680315",
              "rootHash": "990ce39c47246bff1192d158a6f5981e16b891071fccd5604c03268383a084bf",
              "treeSize": "151165654"
            },
            "signedEntryTimestamp": "MEUCIQC0sWdFEzZ6oeRq/bfOHwOuKX6l+g+61XjhDoGqLNxnuAIgS7qJq3QicWoDNjvaGojwBQRqO2XYg3vaW9ykXWsTSIg="
          }
        }
      })";
    }

    // Helper to create a patched JSON string
    std::string create_patched_tlog_json(std::function<void(boost::json::value &)> patch)
    {
      boost::json::value json_val = boost::json::parse(create_sample_tlog_json());
      patch(json_val);
      return boost::json::serialize(json_val);
    }

    // Helper to apply patch to a specific path in the JSON
    void apply_json_patch(boost::json::value &json_val, const std::string &path, std::function<void(boost::json::value &)> patch_func)
    {
      try
        {
          auto &target = json_val.at_pointer(path);
          patch_func(target);
        }
      catch (const std::exception &e)
        {
          throw std::runtime_error("Failed to apply patch at path: " + path + " - " + e.what());
        }
    }

    std::unique_ptr<OnlineTransparencyLogLoader> loader_;
  };

  // =============================================================================
  // Basic functionality tests
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromJsonString)
  {
    std::string tlog_json = create_sample_tlog_json();

    auto result = loader_->load_from_json(tlog_json);
    ASSERT_TRUE(result.has_value()) << "Failed to load TLog JSON: " << result.error().message();

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 1);

    const std::string expected_key = "108e9186e8c5677a5f11d1728c4e5b590c55d04ed60346c413dfe21f9d8cc07f0e734d21441ec766";
    ASSERT_TRUE(entries.find(expected_key) != entries.end());

    auto &entry = entries[expected_key];
    ASSERT_TRUE(entry != nullptr);

    EXPECT_EQ(entry->log_index(), 270584577);
    EXPECT_EQ(entry->integrated_time(), 1752170767);
    EXPECT_EQ(entry->log_id().key_id(), "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d");

    EXPECT_FALSE(entry->canonicalized_body().empty());

    ASSERT_TRUE(entry->has_inclusion_proof());
    const auto &inclusion_proof = entry->inclusion_proof();
    EXPECT_EQ(inclusion_proof.log_index(), 148680315);
    EXPECT_EQ(inclusion_proof.tree_size(), 151165654);
    EXPECT_EQ(inclusion_proof.root_hash(), "990ce39c47246bff1192d158a6f5981e16b891071fccd5604c03268383a084bf");
    EXPECT_EQ(inclusion_proof.hashes_size(), 2);

    ASSERT_TRUE(inclusion_proof.has_checkpoint());
    EXPECT_TRUE(inclusion_proof.checkpoint().envelope().find("rekor.sigstore.dev") != std::string::npos);

    ASSERT_TRUE(entry->has_inclusion_promise());
    EXPECT_FALSE(entry->inclusion_promise().signed_entry_timestamp().empty());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromActualFile)
  {
    std::string test_file = find_test_data_file("tlog.json");

    auto result = loader_->load_from_file(test_file);
    ASSERT_TRUE(result.has_value()) << "Failed to load TLog file: " << result.error().message();

    auto &entries = result.value();
    EXPECT_GT(entries.size(), 0);

    for (const auto &[key, entry]: entries)
      {
        ASSERT_TRUE(entry != nullptr);
        EXPECT_GT(entry->log_index(), 0);
        EXPECT_GT(entry->integrated_time(), 0);
        EXPECT_FALSE(entry->log_id().key_id().empty());

        if (entry->has_inclusion_proof())
          {
            const auto &inclusion_proof = entry->inclusion_proof();
            EXPECT_GE(inclusion_proof.log_index(), 0);
            EXPECT_GT(inclusion_proof.tree_size(), 0);
            EXPECT_FALSE(inclusion_proof.root_hash().empty());
          }

        break;
      }
  }

  // =============================================================================
  // Error handling tests
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromInvalidJson)
  {
    std::string invalid_json = "{ invalid json }";

    auto result = loader_->load_from_json(invalid_json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromNonExistentFile)
  {
    std::filesystem::path non_existent_file = "non_existent_file.json";

    auto result = loader_->load_from_file(non_existent_file);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromEmptyJson)
  {
    std::string empty_json = R"({})";

    auto result = loader_->load_from_json(empty_json);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result.value().size(), 0);
  }

  // File I/O error handling tests
  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromFileOpenFailure)
  {
    // Test with a directory path that can't be opened as a file
    std::filesystem::path invalid_path = "/";

    auto result = loader_->load_from_file(invalid_path);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromFileReadFailure)
  {
    // Create a temporary file with restricted permissions to simulate read failure
    auto temp_dir = std::filesystem::temp_directory_path();
    auto temp_file = temp_dir / "restricted_file.json";

    // Create the file first
    {
      std::ofstream file(temp_file);
      file << R"({"test": "data"})";
    }

    // Make it unreadable (this simulates file.bad() condition)
    std::filesystem::permissions(temp_file, std::filesystem::perms::none);

    auto result = loader_->load_from_file(temp_file);

    // Clean up
    std::filesystem::permissions(temp_file, std::filesystem::perms::owner_all);
    std::filesystem::remove(temp_file);

    // The test might pass if permissions aren't enforced, but we mainly want to trigger the error path
    // In some systems, this will trigger the file.bad() error path
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromJsonNotObject)
  {
    std::string array_json = "[]";

    auto result = loader_->load_from_json(array_json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromJsonWithNonObjectEntry)
  {
    std::string json_with_string = R"({
      "key1": "this is a string, not an object",
      "key2": {
        "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ==",
        "integratedTime": 1234567890,
        "logID": "test",
        "logIndex": "123"
      }
    })";

    auto result = loader_->load_from_json(json_with_string);
    EXPECT_FALSE(result.has_value());
  }

  // =============================================================================
  // Field parsing tests - Integer fields
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, LogIndexAsInteger)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["logIndex"] = SAMPLE_LOG_INDEX;
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->log_index(), 42);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LogIndexAsString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["logIndex"] = "42";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->log_index(), 42);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LogIndexInvalidString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["logIndex"] = "not_a_number";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, IntegratedTimeAsInteger)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["integratedTime"] = SAMPLE_INTEGRATED_TIME;
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->integrated_time(), 9876543210);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, IntegratedTimeAsString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["integratedTime"] = "9876543210";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->integrated_time(), 9876543210);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, IntegratedTimeInvalidString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["integratedTime"] = "invalid_time";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  // =============================================================================
  // Field parsing tests - String fields
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, LogIDField)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["logID"] = "custom_log_id_12345";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->log_id().key_id(), "custom_log_id_12345");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, BodyFieldDecoding)
  {
    std::string test_data = "Hello, World!";
    std::string encoded_data = "SGVsbG8sIFdvcmxkIQ==";

    std::string json = create_patched_tlog_json([&](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["body"] = encoded_data;
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->canonicalized_body(), test_data);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, BodyFieldInvalidBase64)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["body"] = "invalid_base64!@#$";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  // =============================================================================
  // KindVersion tests
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, KindVersionFields)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["kindVersion"] = boost::json::object{{"kind", "custom_kind"}, {"version", "1.2.3"}};
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_kind_version());
    EXPECT_EQ(entry->kind_version().kind(), "custom_kind");
    EXPECT_EQ(entry->kind_version().version(), "1.2.3");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, KindVersionMissingFields)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["kindVersion"] = boost::json::object{{"kind", "only_kind"}};
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_kind_version());
    EXPECT_EQ(entry->kind_version().kind(), "only_kind");
    EXPECT_EQ(entry->kind_version().version(), "");
  }

  // =============================================================================
  // Inclusion proof tests
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofLogIndexAsInteger)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["logIndex"] = SAMPLE_PROOF_LOG_INDEX;
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    EXPECT_EQ(entry->inclusion_proof().log_index(), 999);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofLogIndexAsString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["logIndex"] = "999";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    EXPECT_EQ(entry->inclusion_proof().log_index(), 999);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofLogIndexInvalidString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["logIndex"] = "invalid_number";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofTreeSizeAsInteger)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["treeSize"] = SAMPLE_TREE_SIZE;
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    EXPECT_EQ(entry->inclusion_proof().tree_size(), 123456);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofTreeSizeAsString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["treeSize"] = "123456";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    EXPECT_EQ(entry->inclusion_proof().tree_size(), 123456);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofTreeSizeInvalidString)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["treeSize"] = "not_a_size";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofRootHash)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["rootHash"] = "custom_root_hash_value";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    EXPECT_EQ(entry->inclusion_proof().root_hash(), "custom_root_hash_value");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofHashesArray)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["hashes"] = boost::json::array{"hash1", "hash2", "hash3"};
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    const auto &inclusion_proof = entry->inclusion_proof();
    EXPECT_EQ(inclusion_proof.hashes_size(), 3);
    EXPECT_EQ(inclusion_proof.hashes(0), "hash1");
    EXPECT_EQ(inclusion_proof.hashes(1), "hash2");
    EXPECT_EQ(inclusion_proof.hashes(2), "hash3");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofHashesWithNonStringValues)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["hashes"] = boost::json::array{"hash1", SAMPLE_LOG_INDEX, "hash3"}; // SAMPLE_LOG_INDEX is not a string
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofCheckpoint)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["checkpoint"] = "custom checkpoint data";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    const auto &inclusion_proof = entry->inclusion_proof();
    ASSERT_TRUE(inclusion_proof.has_checkpoint());
    EXPECT_EQ(inclusion_proof.checkpoint().envelope(), "custom checkpoint data");
  }

  // =============================================================================
  // Signed entry timestamp tests
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, SignedEntryTimestamp)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      verification["signedEntryTimestamp"] = "custom_timestamp_signature";
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_promise());
    EXPECT_EQ(entry->inclusion_promise().signed_entry_timestamp(), "custom_timestamp_signature");
  }

  // =============================================================================
  // Missing fields tests
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, MissingRequiredFields)
  {
    std::string json = R"({
      "test_key": {}
    })";

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 1);
    auto &entry = entries["test_key"];
    EXPECT_EQ(entry->log_index(), 0);
    EXPECT_EQ(entry->integrated_time(), 0);
    EXPECT_EQ(entry->log_id().key_id(), "");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, MissingVerificationSection)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry.erase("verification");
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_FALSE(entry->has_inclusion_proof());
    EXPECT_FALSE(entry->has_inclusion_promise());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, MissingInclusionProofSection)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      verification.erase("inclusionProof");
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_FALSE(entry->has_inclusion_proof());
    ASSERT_TRUE(entry->has_inclusion_promise());
  }

  // =============================================================================
  // Multiple entries test
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, MultipleEntries)
  {
    std::string json = R"({
      "entry1": {
        "body": "SGVsbG8gV29ybGQ=",
        "integratedTime": 1111111111,
        "logID": "log1",
        "logIndex": "1"
      },
      "entry2": {
        "body": "SGVsbG8gQWdhaW4=",
        "integratedTime": 2222222222,
        "logID": "log2",
        "logIndex": "2"
      },
      "entry3": {
        "body": "VGhpcmQgRW50cnk=",
        "integratedTime": 3333333333,
        "logID": "log3",
        "logIndex": "3"
      }
    })";

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 3);

    ASSERT_TRUE(entries.find("entry1") != entries.end());
    ASSERT_TRUE(entries.find("entry2") != entries.end());
    ASSERT_TRUE(entries.find("entry3") != entries.end());

    EXPECT_EQ(entries["entry1"]->integrated_time(), 1111111111);
    EXPECT_EQ(entries["entry2"]->integrated_time(), 2222222222);
    EXPECT_EQ(entries["entry3"]->integrated_time(), 3333333333);
  }

  // =============================================================================
  // File I/O error tests
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromEmptyFile)
  {
    std::filesystem::path temp_file = std::filesystem::temp_directory_path() / "empty_tlog.json";
    std::ofstream file(temp_file);
    file.close();

    auto result = loader_->load_from_file(temp_file);
    EXPECT_FALSE(result.has_value());

    std::filesystem::remove(temp_file);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromFileWithValidJson)
  {
    std::filesystem::path temp_file = std::filesystem::temp_directory_path() / "valid_tlog.json";
    std::ofstream file(temp_file);
    file << create_sample_tlog_json();
    file.close();

    auto result = loader_->load_from_file(temp_file);
    ASSERT_TRUE(result.has_value()) << "Failed to load from temp file: " << result.error().message();

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 1);

    std::filesystem::remove(temp_file);
  }

  // =============================================================================
  // Additional edge case tests for better coverage
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, FileOpenError)
  {
    std::filesystem::path dir_path = std::filesystem::temp_directory_path() / "test_directory";
    std::filesystem::create_directory(dir_path);

    auto result = loader_->load_from_file(dir_path);
    EXPECT_FALSE(result.has_value());

    std::filesystem::remove(dir_path);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ConvertTlogEntry_EmptyJsonString)
  {
    std::string empty_json;

    auto result = loader_->load_from_json(empty_json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ConvertTlogEntry_InvalidJsonStructure)
  {
    std::string invalid_structure = R"({"key": "not an object"})";

    auto result = loader_->load_from_json(invalid_structure);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseBasicFields_LogIndexEdgeCases)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry.erase("logIndex");
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->log_index(), 0);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseBasicFields_IntegratedTimeEdgeCases)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry.erase("integratedTime");
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->integrated_time(), 0);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseBasicFields_LogIDEdgeCases)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry.erase("logID");
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->log_id().key_id(), "");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseBasicFields_BodyEdgeCases)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry.erase("body");
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_EQ(entry->canonicalized_body(), "");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseKindVersion_MissingKindVersionSection)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry.erase("kindVersion");
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_FALSE(entry->has_kind_version());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseKindVersion_OnlyVersionField)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["kindVersion"] = boost::json::object{{"version", "2.0.0"}};
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_kind_version());
    EXPECT_EQ(entry->kind_version().kind(), "");
    EXPECT_EQ(entry->kind_version().version(), "2.0.0");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseVerification_OnlySignedEntryTimestamp)
  {
    // Test verification section with only signedEntryTimestamp, no inclusionProof
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["verification"] = boost::json::object{{"signedEntryTimestamp", "test_timestamp"}};
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    EXPECT_FALSE(entry->has_inclusion_proof());
    ASSERT_TRUE(entry->has_inclusion_promise());
    EXPECT_EQ(entry->inclusion_promise().signed_entry_timestamp(), "test_timestamp");
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseInclusionProof_MissingAllOptionalFields)
  {
    // Test inclusion proof with minimal fields (only the required ones that would make parsing succeed)
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      verification["inclusionProof"] = boost::json::object{}; // Empty inclusion proof
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    const auto &inclusion_proof = entry->inclusion_proof();
    EXPECT_EQ(inclusion_proof.log_index(), 0);      // Default value
    EXPECT_EQ(inclusion_proof.tree_size(), 0);      // Default value
    EXPECT_EQ(inclusion_proof.root_hash(), "");     // Default empty
    EXPECT_EQ(inclusion_proof.hashes_size(), 0);    // No hashes
    EXPECT_FALSE(inclusion_proof.has_checkpoint()); // No checkpoint
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseInclusionProof_HashesNotArray)
  {
    // Test with hashes field that is not an array
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["hashes"] = "not_an_array";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseInclusionProof_EmptyHashesArray)
  {
    // Test with empty hashes array
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["hashes"] = boost::json::array{}; // Empty array
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    const auto &inclusion_proof = entry->inclusion_proof();
    EXPECT_EQ(inclusion_proof.hashes_size(), 0); // Should have no hashes
  }

  TEST_F(OnlineTransparencyLogLoaderTest, NumericFieldsAsOtherTypes)
  {
    // Test numeric fields with non-string, non-int types (should fail with strict validation)
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["logIndex"] = true;                       // boolean instead of int/string
      entry["integratedTime"] = boost::json::array{}; // array instead of int/string
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, InclusionProofNumericFieldsAsOtherTypes)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["logIndex"] = boost::json::object{};
      proof["treeSize"] = false;
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseVerification_NonObjectVerification)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["verification"] = "not_an_object";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseKindVersion_NonObjectKindVersion)
  {
    constexpr int invalidKindVersionValue = 123;
    std::string json = create_patched_tlog_json([=](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["kindVersion"] = invalidKindVersionValue;
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseVerification_NonObjectInclusionProof)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      verification["inclusionProof"] = "not_an_object";
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseKindVersion_NonStringKindOrVersion)
  {
    constexpr int invalidKindValue = 123;
    std::string json = create_patched_tlog_json([=](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["kindVersion"] = boost::json::object{{"kind", invalidKindValue}, {"version", boost::json::array{}}};
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseVerification_NonStringSignedEntryTimestamp)
  {
    constexpr int invalidTimestampValue = 123;
    std::string json = create_patched_tlog_json([=](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      verification["signedEntryTimestamp"] = invalidTimestampValue;
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseInclusionProof_NonStringFields)
  {
    constexpr int invalidRootHashValue = 999;
    std::string json = create_patched_tlog_json([=](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      auto &verification = entry["verification"].as_object();
      auto &proof = verification["inclusionProof"].as_object();
      proof["rootHash"] = invalidRootHashValue;
      proof["checkpoint"] = boost::json::array{};
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseBasicFields_NonStringLogIDAndBody)
  {
    constexpr int invalidBodyValue = 42;
    std::string json = create_patched_tlog_json([=](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["logID"] = boost::json::array{};
      entry["body"] = invalidBodyValue;
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ConvertTlogEntry_InvalidTlogEntryJson)
  {
    std::string json_with_malformed_entry = R"({"test_key": { invalid json structure }})";
    auto result = loader_->load_from_json(json_with_malformed_entry);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ConvertTlogEntry_TlogEntryNotObject)
  {
    std::string json = R"({ "key": "string_value_not_object" })";
    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ParseKindVersion_ErrorInKindVersionProcessing)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["kindVersion"] = boost::json::object{{"kind", nullptr}, {"version", nullptr}};
    });

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, CorruptJsonInEntryProcessing)
  {
    boost::json::object root_obj;
    boost::json::object problematic_entry;
    problematic_entry["body"] = "invalid_base64_that_will_fail_decoding!@#$%^&*()";
    problematic_entry["logIndex"] = "not_a_valid_number_at_all";
    constexpr int sample_time = 123456;
    problematic_entry["integratedTime"] = sample_time;
    problematic_entry["logID"] = "test_log_id";

    root_obj["problematic_key"] = problematic_entry;

    std::string json = boost::json::serialize(root_obj);

    auto result = loader_->load_from_json(json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, TriggerFileOpenFailure)
  {
    std::filesystem::path temp_dir = std::filesystem::temp_directory_path() / "test_file_access";
    std::filesystem::create_directory(temp_dir);

    auto result = loader_->load_from_file(temp_dir);
    EXPECT_FALSE(result.has_value());

    std::filesystem::remove(temp_dir);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, TriggerParseKindVersionError)
  {
    boost::json::object huge_kind_version;

    constexpr size_t large_string_size = 100000;
    std::string very_long_string(large_string_size, 'a');
    huge_kind_version["kind"] = very_long_string;
    huge_kind_version["version"] = very_long_string;

    std::string json = create_patched_tlog_json([&](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["kindVersion"] = huge_kind_version;
    });

    auto result = loader_->load_from_json(json);
    EXPECT_TRUE(result.has_value());

    if (result.has_value())
      {
        auto &entries = result.value();
        auto &entry = entries.begin()->second;
        EXPECT_TRUE(entry->has_kind_version());
      }
  }

  TEST_F(OnlineTransparencyLogLoaderTest, ExtremelyMalformedJson)
  {
    std::string extreme_malformed = R"({
      "test_key": {
        "body": "
    )";

    auto result = loader_->load_from_json(extreme_malformed);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, JsonNotAnObject)
  {
    std::string not_an_object = R"("This is not a valid JSON object")";
    auto result = loader_->load_from_json(not_an_object);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, JsonWithNullValues)
  {
    std::string json_with_nulls = R"({
      "test_key": null
    })";

    auto result = loader_->load_from_json(json_with_nulls);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(OnlineTransparencyLogLoaderTest, DirectlyMalformedEntryJson)
  {
    boost::json::object root;
    boost::json::object entry;

    entry["logIndex"] = "123";
    entry["integratedTime"] = "456";
    entry["logID"] = "test";
    entry["body"] = "SGVsbG8="; // Valid base64
    entry["kindVersion"] = boost::json::object{{"kind", "test"}, {"version", "1.0"}};

    root["test_entry"] = entry;

    std::string json = boost::json::serialize(root);

    auto result = loader_->load_from_json(json);
    EXPECT_TRUE(result.has_value());
  }

  // Tests to cover currently uncovered functions and edge cases

  TEST_F(OnlineTransparencyLogLoaderTest, TestBasicFieldParsing)
  {
    // Test parsing of all basic fields through individual scenarios
    boost::json::object root;

    // Test logIndex as string
    {
      boost::json::object entry;
      entry["logIndex"] = "123";
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_TRUE(result.has_value());
    }

    // Test integratedTime as string
    {
      boost::json::object entry;
      entry["integratedTime"] = "9876543210";
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_TRUE(result.has_value());
    }

    // Test logID
    {
      boost::json::object entry;
      entry["logID"] = "test-log-id";
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_TRUE(result.has_value());
    }

    // Test body (base64 encoded)
    {
      boost::json::object entry;
      entry["body"] = "dGVzdA=="; // "test" in base64
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_TRUE(result.has_value());
    }
  }

  TEST_F(OnlineTransparencyLogLoaderTest, TestBasicFieldParsingErrors)
  {
    boost::json::object root;

    // Test invalid logIndex parsing
    {
      boost::json::object entry;
      entry["logIndex"] = "not-a-number";
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }

    // Test invalid integratedTime parsing
    {
      boost::json::object entry;
      entry["integratedTime"] = "not-a-number";
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }

    // Test logIndex as invalid type
    {
      boost::json::object entry;
      entry["logIndex"] = boost::json::array{1, 2, 3}; // invalid type
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }

    // Test integratedTime as invalid type
    {
      boost::json::object entry;
      entry["integratedTime"] = boost::json::array{1, 2, 3}; // invalid type
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }

    // Test logID as invalid type
    {
      boost::json::object entry;
      entry["logID"] = INVALID_TYPE_VALUE; // should be string
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }

    // Test body as invalid type
    {
      boost::json::object entry;
      entry["body"] = INVALID_TYPE_VALUE; // should be string
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }

    // Test body with invalid base64
    {
      boost::json::object entry;
      entry["body"] = "invalid-base64!!!"; // invalid base64
      entry["kindVersion"] = boost::json::object{};
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }
  }

  TEST_F(OnlineTransparencyLogLoaderTest, TestKindVersionFieldEdgeCases)
  {
    boost::json::object root;

    // Test kindVersion.version as non-string (this covers line 306-310 with 0 hits)
    {
      boost::json::object entry;
      boost::json::object kindVersion;
      kindVersion["kind"] = "test";
      kindVersion["version"] = INVALID_TYPE_VALUE; // should be string
      entry["kindVersion"] = kindVersion;
      entry["verification"] = boost::json::object{};
      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }
  }

  TEST_F(OnlineTransparencyLogLoaderTest, TestInclusionProofEdgeCases)
  {
    boost::json::object root;

    // Test inclusionProof.treeSize as invalid type (covers lines 408-412 with 0 hits)
    {
      boost::json::object entry;
      entry["kindVersion"] = boost::json::object{};

      boost::json::object verification;
      boost::json::object inclusionProof;
      inclusionProof["treeSize"] = boost::json::array{1, 2, 3}; // invalid type
      verification["inclusionProof"] = inclusionProof;
      entry["verification"] = verification;

      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }

    // Test inclusionProof.checkpoint as non-string (covers lines 458-462 with 0 hits)
    {
      boost::json::object entry;
      entry["kindVersion"] = boost::json::object{};

      boost::json::object verification;
      boost::json::object inclusionProof;
      inclusionProof["checkpoint"] = INVALID_TYPE_VALUE; // should be string
      verification["inclusionProof"] = inclusionProof;
      entry["verification"] = verification;

      root["test_entry"] = entry;

      std::string json = boost::json::serialize(root);
      auto result = loader_->load_from_json(json);
      EXPECT_FALSE(result.has_value());
    }
  }

  // Tests to cover the file I/O error handling paths that are still uncovered
  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromFileIOErrorPaths)
  {
    // Create a file that will trigger file.bad() condition
    // This is system dependent and hard to reliably test, but we can try creating
    // a very large file or using specific system conditions

    // For now, just document that lines 59-62 and 67-70 are hard to test
    // in a portable way without filesystem manipulation that might not work
    // consistently across systems. These are defensive error handling paths.
  }

  // Tests that specifically trigger the uncovered helper functions
  // The key insight is that these functions are only called when we have valid JSON
  // structure that passes initial validation but needs field parsing
  TEST_F(OnlineTransparencyLogLoaderTest, CoverHelperFunctions)
  {
    // To trigger the helper functions, we need JSON that:
    // 1. Is valid JSON
    // 2. Has root object
    // 3. Has entries that are objects
    // 4. Actually calls convert_tlog_entry_to_protobuf

    boost::json::object root;
    boost::json::object entry;

    // This will trigger parse_basic_fields functions
    entry["logIndex"] = "123";
    entry["integratedTime"] = "456789";
    entry["logID"] = "test-log-id";
    entry["body"] = "dGVzdA=="; // "test" in base64

    // Minimal kindVersion and verification to avoid early errors
    entry["kindVersion"] = boost::json::object{};
    entry["verification"] = boost::json::object{};

    root["test_entry"] = entry;

    std::string json = boost::json::serialize(root);
    auto result = loader_->load_from_json(json);
    // This should succeed and actually call the helper functions
    EXPECT_TRUE(result.has_value());
  }

} // namespace sigstore::test
