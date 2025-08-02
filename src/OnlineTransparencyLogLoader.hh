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

#ifndef ONLINE_TRANSPARENCY_LOG_LOADER_HH
#define ONLINE_TRANSPARENCY_LOG_LOADER_HH

#include <memory>
#include <string>
#include <map>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <boost/outcome/std_result.hpp>
#include <boost/json.hpp>

#include "Logging.hh"
#include "sigstore_rekor.pb.h"

namespace outcome = boost::outcome_v2;

namespace sigstore
{

  class OnlineTransparencyLogLoader
  {
  public:
    using TransparencyLogEntryPtr = std::shared_ptr<dev::sigstore::rekor::v1::TransparencyLogEntry>;
    using TransparencyLogEntryMap = std::map<std::string, TransparencyLogEntryPtr>;

    OnlineTransparencyLogLoader() = default;
    ~OnlineTransparencyLogLoader() = default;

    OnlineTransparencyLogLoader(const OnlineTransparencyLogLoader &) = delete;
    OnlineTransparencyLogLoader &operator=(const OnlineTransparencyLogLoader &) = delete;
    OnlineTransparencyLogLoader(OnlineTransparencyLogLoader &&) noexcept = default;
    OnlineTransparencyLogLoader &operator=(OnlineTransparencyLogLoader &&) noexcept = default;

    outcome::std_result<TransparencyLogEntryMap> load_from_file(const std::filesystem::path &file_path);
    outcome::std_result<TransparencyLogEntryMap> load_from_json(const std::string &json_content);

  private:
    outcome::std_result<TransparencyLogEntryPtr> convert_tlog_entry_to_protobuf(const boost::json::object &tlog_obj);

    outcome::std_result<void> parse_basic_fields(const boost::json::object &tlog_obj, TransparencyLogEntryPtr entry);
    outcome::std_result<void> parse_log_index_field(const boost::json::object &tlog_obj, TransparencyLogEntryPtr entry);
    outcome::std_result<void> parse_integrated_time_field(const boost::json::object &tlog_obj, TransparencyLogEntryPtr entry);
    outcome::std_result<void> parse_log_id_field(const boost::json::object &tlog_obj, TransparencyLogEntryPtr entry);
    outcome::std_result<void> parse_body_field(const boost::json::object &tlog_obj, TransparencyLogEntryPtr entry);
    outcome::std_result<void> parse_kind_version(const boost::json::object &tlog_obj, TransparencyLogEntryPtr entry);
    outcome::std_result<void> parse_verification(const boost::json::object &tlog_obj, TransparencyLogEntryPtr entry);
    outcome::std_result<void> parse_inclusion_proof(const boost::json::object &proof_obj, dev::sigstore::rekor::v1::InclusionProof *inclusion_proof);

    std::shared_ptr<spdlog::logger> logger_{Logging::create("sigstore:online_transparency_log_loader")};
  };

} // namespace sigstore

#endif // ONLINE_TRANSPARENCY_LOG_LOADER_HH
