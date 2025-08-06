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

#include "CanonicalBodyParser.hh"

#include <fstream>
#include <memory>
#include <string>
#include <boost/json.hpp>
#include <boost/outcome/success_failure.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spdlog/logger.h>

#include "TestUtils.hh"
#include "sigstore/Errors.hh"

using namespace sigstore;

class CanonicalBodyParserTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    parser_ = std::make_unique<CanonicalBodyParser>();
  }

  std::string load_body_json()
  {
    std::string file_path = find_test_data_file("body.json");
    std::ifstream body_file(file_path);
    if (!body_file.is_open())
      {
        ADD_FAILURE() << "Failed to open body.json file: " << file_path;
        return "";
      }

    std::string body_json_str((std::istreambuf_iterator<char>(body_file)), std::istreambuf_iterator<char>());
    body_file.close();
    return body_json_str;
  }

  outcome::std_result<LogEntry> load_and_parse(std::function<void(boost::json::value &json_val)> patch = [](boost::json::value &json_val) {})
  {
    std::string body_json_str = load_body_json();
    if (body_json_str.empty())
      {
        return SigstoreError::InvalidTransparencyLog;
      }

    try
      {
        boost::json::value json_val = boost::json::parse(body_json_str);
        if (json_val.is_null())
          {
            ADD_FAILURE() << "Failed to parse JSON from body file";
            return SigstoreError::InvalidTransparencyLog;
          }

        try
          {
            patch(json_val);
          }
        catch (const std::exception &e)
          {
            ADD_FAILURE() << "Failed to apply patch to JSON: " << e.what();
            return SigstoreError::InvalidTransparencyLog;
          }

        std::string patched_json = boost::json::serialize(json_val);
        return parser_->parse_from_json(patched_json);
      }
    catch (const std::exception &e)
      {
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  void apply_json_patch(boost::json::value &json_val, const std::string &json_pointer, std::function<void(boost::json::object &)> patch_func) const
  {
    try
      {
        auto &target_obj = json_val.at_pointer(json_pointer).as_object();
        patch_func(target_obj);
      }
    catch (const std::exception &e)
      {
        spdlog::error("Failed to apply patch at path {}: {}", json_pointer, e.what());
        throw std::runtime_error("Failed to apply patch at path: " + json_pointer + " - " + e.what());
      }
  }

  std::unique_ptr<CanonicalBodyParser> parser_;
};

// =============================================================================
// Valid JSON
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseValidBodyJson)
{
  auto result = load_and_parse();
  ASSERT_TRUE(result.has_value()) << "Failed to parse valid body.json: " << result.error().message();

  const auto &log_entry = result.value();
  EXPECT_EQ(log_entry.kind, "hashedrekord");
  EXPECT_EQ(log_entry.api_version, "0.0.1");

  ASSERT_TRUE(std::holds_alternative<HashedRekord>(log_entry.spec));
  const auto &hashed_rekord = std::get<HashedRekord>(log_entry.spec);
  EXPECT_EQ(hashed_rekord.hash_algorithm, "sha256");
  EXPECT_EQ(hashed_rekord.hash_value, "64b5b3787599e6d9bed0c8de28d7ddf0c300c40fc0e2a10a90d7fb90e41acb20");
  EXPECT_FALSE(hashed_rekord.signature.empty());
  EXPECT_FALSE(hashed_rekord.public_key.empty());
}

// =============================================================================
// Invalid JSON Structure
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseInvalidJson)
{
  auto result = parser_->parse_from_json("invalid json");
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseEmptyJson)
{
  auto result = parser_->parse_from_json("");
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseJsonArray)
{
  auto result = parser_->parse_from_json("[]");
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseJsonString)
{
  auto result = parser_->parse_from_json("\"string\"");
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseJsonNumber)
{
  auto result = parser_->parse_from_json("123");
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseJsonNull)
{
  auto result = parser_->parse_from_json("null");
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

// =============================================================================
// Missing Required Fields
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseMissingKind)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.erase(obj.find("kind"));
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseMissingApiVersion)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.erase(obj.find("apiVersion"));
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseMissingSpec)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.erase(obj.find("spec"));
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

// =============================================================================
// Invalid Field Types
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseKindWrongType)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj["kind"] = 123;
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseApiVersionWrongType)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj["apiVersion"] = true;
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseSpecWrongType)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj["spec"] = "invalid-spec";
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

// =============================================================================
// Unsupported Entry Kind/Version
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseUnsupportedKind)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj["kind"] = "unsupported_kind";
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseUnsupportedVersion)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj["apiVersion"] = "99.99.99";
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseSupportedKindUnsupportedVersion)
{
  auto result = load_and_parse([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj["kind"] = "hashedrekord";
    obj["apiVersion"] = "1.0.0";
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

// =============================================================================
// HashedRekord Spec Tests - Missing Fields
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingData)
{
  auto result = load_and_parse(
    [this](boost::json::value &json_val) { apply_json_patch(json_val, "/spec", [](boost::json::object &obj) { obj.erase(obj.find("data")); }); });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingHash)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/data", [](boost::json::object &obj) { obj.erase(obj.find("hash")); });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingHashAlgorithm)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/data/hash", [](boost::json::object &obj) { obj.erase(obj.find("algorithm")); });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingHashValue)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/data/hash", [](boost::json::object &obj) { obj.erase(obj.find("value")); });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingSignature)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec", [](boost::json::object &obj) { obj.erase(obj.find("signature")); });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingSignatureContent)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature", [](boost::json::object &obj) { obj.erase(obj.find("content")); });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingPublicKey)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature", [](boost::json::object &obj) { obj.erase(obj.find("publicKey")); });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordMissingPublicKeyContent)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature/publicKey", [](boost::json::object &obj) { obj.erase(obj.find("content")); });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

// =============================================================================
// HashedRekord Spec Tests - Wrong Types
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseHashedRekordDataWrongType)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec", [](boost::json::object &obj) { obj["data"] = "invalid-data-type"; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordHashWrongType)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/data", [](boost::json::object &obj) { obj["hash"] = "invalid-hash-type"; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordHashAlgorithmWrongType)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/data/hash", [](boost::json::object &obj) { obj["algorithm"] = 256; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordHashValueWrongType)
{
  auto result = load_and_parse(
    [this](boost::json::value &json_val) { apply_json_patch(json_val, "/spec/data/hash", [](boost::json::object &obj) { obj["value"] = false; }); });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordSignatureWrongType)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec", [](boost::json::object &obj) { obj["signature"] = "invalid-signature-type"; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordSignatureContentWrongType)
{
  auto result = load_and_parse(
    [this](boost::json::value &json_val) { apply_json_patch(json_val, "/spec/signature", [](boost::json::object &obj) { obj["content"] = 123; }); });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordPublicKeyWrongType)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature", [](boost::json::object &obj) { obj["publicKey"] = "invalid-public-key-type"; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordPublicKeyContentWrongType)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature/publicKey", [](boost::json::object &obj) { obj["content"] = 456; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

// =============================================================================
// Base64 Decoding Tests
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseHashedRekordInvalidSignatureBase64)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature", [](boost::json::object &obj) { obj["content"] = "invalid-base64-content!@#"; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseHashedRekordInvalidPublicKeyBase64)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature/publicKey", [](boost::json::object &obj) { obj["content"] = "invalid-base64-content!@#"; });
  });
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

// =============================================================================
// Edge Cases
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseEmptyStringFields)
{
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/data/hash", [](boost::json::object &obj) {
      obj["algorithm"] = "";
      obj["value"] = "";
    });
    apply_json_patch(json_val, "/spec/signature", [](boost::json::object &obj) { obj["content"] = ""; });
    apply_json_patch(json_val, "/spec/signature/publicKey", [](boost::json::object &obj) { obj["content"] = ""; });
  });
  ASSERT_TRUE(result.has_value()) << "Failed to parse with empty string fields: " << result.error().message();

  const auto &log_entry = result.value();
  ASSERT_TRUE(std::holds_alternative<HashedRekord>(log_entry.spec));
  const auto &hashed_rekord = std::get<HashedRekord>(log_entry.spec);
  EXPECT_EQ(hashed_rekord.hash_algorithm, "");
  EXPECT_EQ(hashed_rekord.hash_value, "");
  EXPECT_EQ(hashed_rekord.signature, "");
  EXPECT_EQ(hashed_rekord.public_key, "");
}

TEST_F(CanonicalBodyParserTest, ParseValidBase64EmptyContent)
{
  // Valid base64 that decodes to empty string
  auto result = load_and_parse([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/spec/signature", [](boost::json::object &obj) {
      obj["content"] = ""; // Empty base64 should decode to empty string
    });
    apply_json_patch(json_val, "/spec/signature/publicKey", [](boost::json::object &obj) {
      obj["content"] = ""; // Empty base64 should decode to empty string
    });
  });
  ASSERT_TRUE(result.has_value()) << "Failed to parse with valid base64 empty content: " << result.error().message();

  const auto &log_entry = result.value();
  ASSERT_TRUE(std::holds_alternative<HashedRekord>(log_entry.spec));
  const auto &hashed_rekord = std::get<HashedRekord>(log_entry.spec);
  EXPECT_EQ(hashed_rekord.signature, "");
  EXPECT_EQ(hashed_rekord.public_key, "");
}

TEST_F(CanonicalBodyParserTest, ParseMinimalValidJson)
{
  std::string minimal_json = R"({
    "kind": "hashedrekord",
    "apiVersion": "0.0.1",
    "spec": {
      "data": {
        "hash": {
          "algorithm": "sha256",
          "value": "test"
        }
      },
      "signature": {
        "content": "dGVzdA==",
        "publicKey": {
          "content": "dGVzdA=="
        }
      }
    }
  })";

  auto result = parser_->parse_from_json(minimal_json);
  ASSERT_TRUE(result.has_value()) << "Failed to parse minimal valid JSON: " << result.error().message();

  const auto &log_entry = result.value();
  EXPECT_EQ(log_entry.kind, "hashedrekord");
  EXPECT_EQ(log_entry.api_version, "0.0.1");

  ASSERT_TRUE(std::holds_alternative<HashedRekord>(log_entry.spec));
  const auto &hashed_rekord = std::get<HashedRekord>(log_entry.spec);
  EXPECT_EQ(hashed_rekord.hash_algorithm, "sha256");
  EXPECT_EQ(hashed_rekord.hash_value, "test");
  EXPECT_EQ(hashed_rekord.signature, "test");  // Base64 decode of "dGVzdA=="
  EXPECT_EQ(hashed_rekord.public_key, "test"); // Base64 decode of "dGVzdA=="
}

// =============================================================================
// Exception Handling Tests
// =============================================================================

TEST_F(CanonicalBodyParserTest, ParseJsonWithMalformedStructure)
{
  // Test that we handle JSON parsing exceptions gracefully
  auto result = parser_->parse_from_json("{\"key\": }"); // Malformed JSON
  ASSERT_TRUE(result.has_error());
  EXPECT_EQ(result.error(), SigstoreError::InvalidTransparencyLog);
}

TEST_F(CanonicalBodyParserTest, ParseJsonWithUnicodeEscape)
{
  // Test JSON with unicode escape sequences
  std::string unicode_json = R"({
    "kind": "hashedrekord",
    "apiVersion": "0.0.1",
    "spec": {
      "data": {
        "hash": {
          "algorithm": "sha256",
          "value": "\u0074\u0065\u0073\u0074"
        }
      },
      "signature": {
        "content": "dGVzdA==",
        "publicKey": {
          "content": "dGVzdA=="
        }
      }
    }
  })";

  auto result = parser_->parse_from_json(unicode_json);
  ASSERT_TRUE(result.has_value()) << "Failed to parse JSON with unicode: " << result.error().message();

  const auto &log_entry = result.value();
  ASSERT_TRUE(std::holds_alternative<HashedRekord>(log_entry.spec));
  const auto &hashed_rekord = std::get<HashedRekord>(log_entry.spec);
  EXPECT_EQ(hashed_rekord.hash_value, "test"); // Unicode escape should decode to "test"
}
