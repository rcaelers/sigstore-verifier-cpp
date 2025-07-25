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

#ifndef REKOR_TRANSACTION_LOG_LOADER_HH
#define REKOR_TRANSACTION_LOG_LOADER_HH

#include <boost/outcome/std_result.hpp>
#include <memory>
#include <string>
#include <filesystem>

#include <spdlog/spdlog.h>
#include "Logging.hh"

#include "sigstore_rekor.pb.h"

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  class TransparencyLogLoader
  {
  public:
    TransparencyLogLoader() = default;
    ~TransparencyLogLoader() = default;

    TransparencyLogLoader(const TransparencyLogLoader &) = delete;
    TransparencyLogLoader &operator=(const TransparencyLogLoader &) = delete;
    TransparencyLogLoader(TransparencyLogLoader &&) noexcept = default;
    TransparencyLogLoader &operator=(TransparencyLogLoader &&) noexcept = default;

    outcome::std_result<std::unique_ptr<dev::sigstore::rekor::v1::TransparencyLogEntry>> load_from_file(const std::filesystem::path &file_path);
    outcome::std_result<std::unique_ptr<dev::sigstore::rekor::v1::TransparencyLogEntry>> load_from_json(const std::string &json_content);

  private:
    std::shared_ptr<spdlog::logger> logger_{Logging::create("sigstore:rekor_transaction_log_loader")};
  };

} // namespace sigstore

#endif // REKOR_TRANSACTION_LOG_LOADER_HH
