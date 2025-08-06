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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "sigstore/Bundle.hh"
#include "sigstore/Context.hh"
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif

#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif
#include <spdlog/fmt/ostr.h>

using namespace sigstore;
using namespace testing;

#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#  include <windows.h>
#endif

#include <chrono>
#include <fstream>
#include <memory>
#include <string>
#include <tuple>
#include <boost/json.hpp>
#include <boost/outcome/success_failure.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spdlog/logger.h>

#include "TestUtils.hh"
#include "sigstore/Errors.hh"

struct GlobalSigStoreTest : public ::testing::Environment
{
  GlobalSigStoreTest() = default;
  ~GlobalSigStoreTest() override = default;

  GlobalSigStoreTest(const GlobalSigStoreTest &) = delete;
  GlobalSigStoreTest &operator=(const GlobalSigStoreTest &) = delete;
  GlobalSigStoreTest(GlobalSigStoreTest &&) = delete;
  GlobalSigStoreTest &operator=(GlobalSigStoreTest &&) = delete;

  void SetUp() override
  {
    // #ifdef _WIN32
    //     // Set console to UTF-8 for proper Unicode display (only do this once)
    //     static bool utf8_initialized = false;
    //     if (!utf8_initialized)
    //       {
    //         // Set console code page to UTF-8
    //         SetConsoleOutputCP(CP_UTF8);
    //         SetConsoleCP(CP_UTF8);

    //         // Enable UTF-8 for stdout/stderr
    //         _setmode(_fileno(stdout), _O_U8TEXT);
    //         _setmode(_fileno(stderr), _O_U8TEXT);

    //         utf8_initialized = true;
    //       }
    // #endif

    const auto *log_file = "test-sigstore.log";

    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    auto logger{std::make_shared<spdlog::logger>("sigstore", std::initializer_list<spdlog::sink_ptr>{file_sink, console_sink})};
    logger->flush_on(spdlog::level::critical);
    logger->set_level(spdlog::level::debug);
    spdlog::set_default_logger(logger);

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%-5l%$] %v");

#if SPDLOG_VERSION >= 10801
    spdlog::cfg::load_env_levels();
#endif
    logger->info("Sigstore test environment initialized");
  }

  void TearDown() override
  {
    spdlog::drop_all();
  }
};

::testing::Environment *const global_env = ::testing::AddGlobalTestEnvironment(new GlobalSigStoreTest);

class SigstoreTest : public ::testing::Test
{
public:
protected:
  void SetUp() override
  {
    verifier = sigstore::Context::instance_default();
    [[maybe_unused]] auto result = verifier->load_embedded_fulcio_ca_certificates();
  }

  void TearDown() override
  {
  }

  outcome::std_result<std::tuple<std::string, std::string>> load_standard_bundle(std::function<void(boost::json::value &json_val)> patch =
                                                                                   [](boost::json::value &json_val) {})
  {
    std::string file_path = find_test_data_file("appcast-sigstore.xml.sigstore.bundle");
    std::ifstream bundle_file(file_path);
    if (!bundle_file.is_open())
      {
        ADD_FAILURE() << "Failed to open bundle file: " << file_path;
        return SigstoreError::InvalidBundle;
      }

    std::string bundle_json_str((std::istreambuf_iterator<char>(bundle_file)), std::istreambuf_iterator<char>());
    bundle_file.close();

    std::string data_file_path = find_test_data_file("appcast-sigstore.xml");
    std::ifstream data_file(data_file_path);
    if (!data_file.is_open())
      {
        ADD_FAILURE() << "Failed to open data file: " << data_file_path;
        return SigstoreError::InvalidBundle;
      }

    std::string data((std::istreambuf_iterator<char>(data_file)), std::istreambuf_iterator<char>());
    data_file.close();

    try
      {
        boost::json::value json_val = boost::json::parse(bundle_json_str);

        if (json_val.is_null())
          {
            ADD_FAILURE() << "Failed to parse JSON from bundle file: " << file_path;
            return SigstoreError::InvalidBundle;
          }
        try
          {
            patch(json_val);
          }
        catch (const std::exception &e)
          {
            ADD_FAILURE() << "Failed to apply patch to JSON: " << e.what();
            return SigstoreError::InvalidBundle;
          }
        return {boost::json::serialize(json_val), data};
      }
    catch (const std::exception &e)
      {
        return SigstoreError::InvalidBundle;
      }
  }

  void apply_json_patch(boost::json::value &json_val, const std::string &bundle_patch, std::function<void(boost::json::object &)> patch_func) const
  {
    try
      {
        auto &target_obj = json_val.at_pointer(bundle_patch).as_object();
        patch_func(target_obj);
      }
    catch (const std::exception &e)
      {
        spdlog::error("Failed to apply patch at path {}: {}", bundle_patch, e.what());
        throw std::runtime_error("Failed to apply patch at path: " + bundle_patch + " - " + e.what());
      }
  }

  std::shared_ptr<Context> verifier;
};

TEST_F(SigstoreTest, ParseStandardBundleFormat)
{
  std::string bundle_path = find_test_data_file("appcast-sigstore.xml.sigstore.bundle");
  std::ifstream bundle_file(bundle_path);
  ASSERT_TRUE(bundle_file.is_open()) << "Failed to open standard bundle at: " << bundle_path;
  std::string bundle_json((std::istreambuf_iterator<char>(bundle_file)), std::istreambuf_iterator<char>());
  bundle_file.close();

  std::string content_path = find_test_data_file("appcast-sigstore.xml");
  std::ifstream content_file(content_path);
  ASSERT_TRUE(content_file.is_open()) << "Failed to open content file at: " << content_path;
  std::string content((std::istreambuf_iterator<char>(content_file)), std::istreambuf_iterator<char>());
  content_file.close();

  try
    {
      auto context = sigstore::Context::instance_default();
      auto bundle_result = sigstore::Bundle::create(context, bundle_json);
      ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
      auto bundle = bundle_result.value();

      auto result = bundle->verify(content);
      EXPECT_FALSE(result.has_error()) << "Failed to verify bundle: " << result.error().message();
    }
  catch (std::exception &e)
    {
      spdlog::info("Exception {}", e.what());
      EXPECT_TRUE(false);
    }
}

// =============================================================================
// Valid JSON
// =============================================================================

TEST_F(SigstoreTest, ValidateValidLog)
{
  auto log = this->load_standard_bundle();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data";
  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result) << "Failed to verify transparency log: " << result.error().message();
}

TEST_F(SigstoreTest, ValidateValidBundle)
{
  auto log = this->load_standard_bundle();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data";
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result);
}

TEST_F(SigstoreTest, ValidateValidBundleInvalidData)
{
  auto log = this->load_standard_bundle();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data";
  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data + "x");
  ASSERT_FALSE(result);
}

TEST_F(SigstoreTest, ValidateValidBundleNoRootCertificate)
{
  auto context = sigstore::Context::instance();
  auto log = this->load_standard_bundle();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data";
  auto &[bundle_json, data] = log.value();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_FALSE(result);
}

// TODO: other root/intermwediate

// =============================================================================
// Inalid JSON
// =============================================================================

TEST_F(SigstoreTest, ValidateLog_NoVerificationMaterial)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "", [](boost::json::object &obj) { obj.erase(obj.find("verificationMaterial")); });
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionProof)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.erase(obj.find("inclusionProof")); });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofWrongType)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.erase(obj.find("inclusionProof"));
      obj["inclusionProof"] = "invalid-type";
    });
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionProofCheckPoint)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("checkpoint"));
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionProofCanonicalizedBody)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      auto *it = obj.find("canonicalizedBody");
      if (it != obj.end())
        {
          obj.erase(it);
        }
      else
        {
          auto *body_it = obj.find("body");
          if (body_it != obj.end())
            {
              obj.erase(body_it);
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCanonicalizedBody)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      auto *it = obj.find("canonicalizedBody");
      if (it != obj.end())
        {
          it->value() = "invalid-base64";
        }
      else
        {
          auto *body_it = obj.find("body");
          if (body_it != obj.end())
            {
              body_it->value() = "invalid-base64";
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionProofLogIndex)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("logIndex"));
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofLogIndex1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("logIndex")->value() = "0";
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofLogIndex2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("logIndex")->value() = "999999999";
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofLogIndex3)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("logIndex")->value() = "foo";
    });
  });
  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionProofTreeSize)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("treeSize"));
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofTreeSize1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("treeSize")->value() = "0";
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofTreeSize2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("treeSize")->value() = "999999999";
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofTreeSize3)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("treeSize")->value() = "foo";
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionProofRootHash)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("rootHash"));
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofRootHash)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("rootHash")->value() = "foo";
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionProofHashes)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) { obj.erase(obj.find("hashes")); });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofHashes)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      auto &hashes = obj.find("hashes")->value().as_array();
      hashes[0] = "invalid-hash";
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_EmptyInclusionProofHashes)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("hashes")->value() = boost::json::array{};
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpoint1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = "invalid-checkpoint-envelope";
            }
          else
            {
              checkpoint_it->value() = "invalid-checkpoint-envelope";
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpoint2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = "";
            }
          else
            {
              checkpoint_it->value() = "";
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpointInconsistentTreeSize)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n148680320\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = envelope_value;
            }
          else
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n15116574\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
              checkpoint_it->value() = envelope_value;
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpointTreeSizeWrongType)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\nx148680320\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = envelope_value;
            }
          else
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\nx15116564\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
              checkpoint_it->value() = envelope_value;
            }
        }
    });
  });

  auto context = sigstore::Context::instance_default();
  auto &[bundle_json, data] = log.value();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpointNoBody)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              const auto *envelope_value =
                "\n\nrekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = envelope_value;
            }
          else
            {
              const auto *envelope_value =
                "\n\nrekor.sigstore.dev - 1193050959916656506\n15116564\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
              checkpoint_it->value() = envelope_value;
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpointNoSeparator)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = envelope_value;
            }
          else
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n15116564\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
              checkpoint_it->value() = envelope_value;
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpointNoNewLine)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=";
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = envelope_value;
            }
          else
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n151165654\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC";
              checkpoint_it->value() = envelope_value;
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionProofCheckpointWrongSignature)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      auto *checkpoint_it = obj.find("checkpoint");
      if (checkpoint_it != obj.end())
        {
          if (checkpoint_it->value().is_object())
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\nx rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=";
              auto &checkpoint_obj = checkpoint_it->value().as_object();
              checkpoint_obj.find("envelope")->value() = envelope_value;
            }
          else
            {
              const auto *envelope_value =
                "rekor.sigstore.dev - 1193050959916656506\n151165654\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\nx rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC";
              checkpoint_it->value() = envelope_value;
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

// =============================================================================
// Top-level mediaType Tests
// =============================================================================

TEST_F(SigstoreTest, ValidateLog_NoMediaType)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.erase(obj.find("mediaType"));
  });
  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidMediaType)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.find("mediaType")->value() = "invalid/media-type";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

// =============================================================================
// Certificate Tests
// =============================================================================

TEST_F(SigstoreTest, ValidateLog_NoCertificate)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.erase(obj.find("certificate"));
  });
  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoCertificateRawBytes)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/certificate").as_object();
    obj.erase(obj.find("rawBytes"));
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidCertificateRawBytes)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/certificate").as_object();
    obj.find("rawBytes")->value() = "invalid-certificate-data";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

// =============================================================================
// tlogEntries Tests
// =============================================================================

TEST_F(SigstoreTest, ValidateLog_NoTlogEntries)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.erase(obj.find("tlogEntries"));
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_EmptyTlogEntries)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.find("tlogEntries")->value() = boost::json::array{};
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoTlogEntryLogIndex)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.erase(obj.find("logIndex")); });
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidTlogEntryLogIndex)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.find("logIndex")->value() = "invalid-log-index";
    });
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoLogId)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      auto *it = obj.find("logId");
      if (it != obj.end())
        {
          obj.erase(it);
        }
      else
        {
          auto *it_api = obj.find("logID");
          if (it_api != obj.end())
            {
              obj.erase(it_api);
            }
        }
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_LogIdWrongType)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      auto *it = obj.find("logId");
      obj.erase(it);
      obj["logId"] = "invalid-log-id-type";
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoLogIdKeyId)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0/logId").as_object();
    obj.erase(obj.find("keyId"));
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidLogIdKeyId)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0/logId").as_object();
    obj.find("keyId")->value() = "invalid-key-id";
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoKindVersion)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    obj.erase(obj.find("kindVersion"));
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidKindVersionWrongType)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("kindVersion"));
    o["kindVersion"] = "invalid-kind-version-type";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoKindVersionKind)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.erase(o.find("kind"));
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidKindVersionKind)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.find("kind")->value() = "invalid-kind";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoKindVersionVersion)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.erase(o.find("version"));
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidKindVersionVersion)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.find("version")->value() = "invalid-version";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoIntegratedTime)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.erase(obj.find("integratedTime")); });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidIntegratedTime1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.find("integratedTime")->value() = "invalid-time";
    });
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidIntegratedTime2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.find("integratedTime")->value() = true; });
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_IntegratedTimeOutOfRange)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.find("integratedTime")->value() = "1752174767";
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_IntegratedTimeFuture)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      auto current_time = std::chrono::system_clock::now();
      auto out_of_range_time = std::chrono::duration_cast<std::chrono::seconds>(current_time.time_since_epoch()).count() + 1000000;
      obj.find("integratedTime")->value() = std::to_string(out_of_range_time);
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionPromise)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("inclusionPromise"));
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InclusionPromiseWrongType)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("inclusionPromise"));
    o["inclusionPromise"] = "invalid-inclusion-promise-type";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoInclusionPromiseSignedEntryTimestamp)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionPromise", [](boost::json::object &obj) {
      obj.erase(obj.find("signedEntryTimestamp"));
    });
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_TRUE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidInclusionPromiseSignedEntryTimestamp)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionPromise", [](boost::json::object &obj) {
      obj.find("signedEntryTimestamp")->value() = "invalid-timestamp";
    });
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

// =============================================================================
// messageSignature Tests
// =============================================================================

TEST_F(SigstoreTest, ValidateLog_NoMessageSignature)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.as_object();
    o.erase(o.find("messageSignature"));
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoMessageDigest)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.erase(o.find("messageDigest"));
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoMessageDigestAlgorithm)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.erase(o.find("algorithm"));
  });

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidMessageDigestAlgorithm)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.find("algorithm")->value() = "INVALID_ALGO";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoMessageDigestDigest)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.erase(o.find("digest"));
  });
  ASSERT_FALSE(log.has_error());

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();

  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidMessageDigestDigest)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.find("digest")->value() = "invalid-digest";
  });
  ASSERT_FALSE(log.has_error());

  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_FALSE(bundle_result.has_error()) << "Failed to create bundle: " << bundle_result.error().message();
  auto bundle = bundle_result.value();
  auto result = bundle->verify(data);
  ASSERT_FALSE(result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_NoMessageSignatureSignature)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.erase(o.find("signature"));
  });
  auto &[bundle_json, data] = log.value();

  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}

TEST_F(SigstoreTest, ValidateLog_InvalidMessageSignatureSignature)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.find("signature")->value() = "invalid-signature";
  });
  auto &[bundle_json, data] = log.value();
  auto context = sigstore::Context::instance_default();
  auto bundle_result = sigstore::Bundle::create(context, bundle_json);
  ASSERT_TRUE(bundle_result.has_error());
}
