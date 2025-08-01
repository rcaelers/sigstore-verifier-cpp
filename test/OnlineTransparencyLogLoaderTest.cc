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
#include <filesystem>
#include <fstream>
#include <boost/json.hpp>

#include "OnlineTransparencyLogLoader.hh"
#include "TestUtils.hh"

namespace sigstore::test
{

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

    // Verify basic fields
    EXPECT_EQ(entry->log_index(), 270584577);
    EXPECT_EQ(entry->integrated_time(), 1752170767);
    EXPECT_EQ(entry->log_id().key_id(), "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d");

    // Verify canonicalized body is decoded
    EXPECT_FALSE(entry->canonicalized_body().empty());

    // Verify inclusion proof
    ASSERT_TRUE(entry->has_inclusion_proof());
    const auto &inclusion_proof = entry->inclusion_proof();
    EXPECT_EQ(inclusion_proof.log_index(), 148680315);
    EXPECT_EQ(inclusion_proof.tree_size(), 151165654);
    EXPECT_EQ(inclusion_proof.root_hash(), "990ce39c47246bff1192d158a6f5981e16b891071fccd5604c03268383a084bf");
    EXPECT_EQ(inclusion_proof.hashes_size(), 2);

    // Verify checkpoint
    ASSERT_TRUE(inclusion_proof.has_checkpoint());
    EXPECT_TRUE(inclusion_proof.checkpoint().envelope().find("rekor.sigstore.dev") != std::string::npos);

    // Verify signed entry timestamp
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

        // Just verify one entry in detail
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
    std::string empty_json = "{}";

    auto result = loader_->load_from_json(empty_json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 0);
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
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 1); // Only key2 should be loaded
    EXPECT_TRUE(entries.find("key2") != entries.end());
    EXPECT_TRUE(entries.find("key1") == entries.end());
  }

  // =============================================================================
  // Field parsing tests - Integer fields
  // =============================================================================

  TEST_F(OnlineTransparencyLogLoaderTest, LogIndexAsInteger)
  {
    std::string json = create_patched_tlog_json([](boost::json::value &json_val) {
      auto &entry = json_val.as_object().begin()->value().as_object();
      entry["logIndex"] = 42;
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
      entry["integratedTime"] = 9876543210;
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
    // Create a simple base64 encoded string
    std::string test_data = "Hello, World!";
    std::string encoded_data = "SGVsbG8sIFdvcmxkIQ=="; // base64 of "Hello, World!"

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
    EXPECT_EQ(entry->kind_version().version(), ""); // Default empty
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
      proof["logIndex"] = 999;
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
      proof["treeSize"] = 123456;
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
      proof["hashes"] = boost::json::array{"hash1", 42, "hash3"}; // 42 is not a string
    });

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    auto &entry = entries.begin()->second;
    ASSERT_TRUE(entry->has_inclusion_proof());
    const auto &inclusion_proof = entry->inclusion_proof();
    EXPECT_EQ(inclusion_proof.hashes_size(), 2); // Only string values should be added
    EXPECT_EQ(inclusion_proof.hashes(0), "hash1");
    EXPECT_EQ(inclusion_proof.hashes(1), "hash3");
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
    // Test with minimal valid entry (no required fields enforced by parser)
    std::string json = R"({
      "test_key": {}
    })";

    auto result = loader_->load_from_json(json);
    ASSERT_TRUE(result.has_value());

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 1);
    auto &entry = entries["test_key"];
    EXPECT_EQ(entry->log_index(), 0);        // Default value
    EXPECT_EQ(entry->integrated_time(), 0);  // Default value
    EXPECT_EQ(entry->log_id().key_id(), ""); // Default empty
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
    ASSERT_TRUE(entry->has_inclusion_promise()); // signedEntryTimestamp should still be there
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
    // Create a temporary empty file
    std::filesystem::path temp_file = std::filesystem::temp_directory_path() / "empty_tlog.json";
    std::ofstream file(temp_file);
    file.close();

    auto result = loader_->load_from_file(temp_file);
    EXPECT_FALSE(result.has_value()); // Empty file should fail JSON parsing

    // Clean up
    std::filesystem::remove(temp_file);
  }

  TEST_F(OnlineTransparencyLogLoaderTest, LoadFromFileWithValidJson)
  {
    // Create a temporary file with valid JSON
    std::filesystem::path temp_file = std::filesystem::temp_directory_path() / "valid_tlog.json";
    std::ofstream file(temp_file);
    file << create_sample_tlog_json();
    file.close();

    auto result = loader_->load_from_file(temp_file);
    ASSERT_TRUE(result.has_value()) << "Failed to load from temp file: " << result.error().message();

    auto &entries = result.value();
    EXPECT_EQ(entries.size(), 1);

    // Clean up
    std::filesystem::remove(temp_file);
  }

} // namespace sigstore::test
