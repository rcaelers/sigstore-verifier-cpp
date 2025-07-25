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

#include "sigstore/SigstoreVerifier.hh"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
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
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#endif

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
  }

  void TearDown() override
  {
  }
};

TEST_F(SigstoreTest, ParseStandardBundleFormat)
{
  SigstoreVerifier verifier;

  std::ifstream bundle_file("appcast-sigstore.xml.sigstore.new.bundle");
  ASSERT_TRUE(bundle_file.is_open()) << "Failed to open standard bundle";
  std::string bundle_json((std::istreambuf_iterator<char>(bundle_file)), std::istreambuf_iterator<char>());
  bundle_file.close();

  std::ifstream content_file("appcast-sigstore.xml");
  ASSERT_TRUE(content_file.is_open()) << "Failed to open content file";
  std::string content((std::istreambuf_iterator<char>(content_file)), std::istreambuf_iterator<char>());
  content_file.close();

  try
    {
      auto result = verifier.verify(content, bundle_json);
      EXPECT_TRUE(result.has_value()) << "Failed to verify legacy bundle: " << result.error().message();
      EXPECT_TRUE(result.value());
    }
  catch (std::exception &e)
    {
      spdlog::info("Exception {}", e.what());
      EXPECT_TRUE(false);
    }
}
