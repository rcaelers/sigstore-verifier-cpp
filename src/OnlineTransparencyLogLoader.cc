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

#include <fstream>
#include <boost/json.hpp>
#include <google/protobuf/util/json_util.h>

#include "sigstore/SigstoreErrors.hh"
#include "Base64.hh"

namespace sigstore
{

  namespace
  {
    outcome::std_result<int64_t> parse_int64(const std::string &str)
    {
      try
        {
          return std::stoll(str);
        }
      catch (const std::exception &)
        {
          return SigstoreError::InvalidTransparencyLog;
        }
    }
  } // namespace

  outcome::std_result<OnlineTransparencyLogLoader::TransparencyLogEntryMap> OnlineTransparencyLogLoader::load_from_file(
    const std::filesystem::path &file_path)
  {
    if (!std::filesystem::exists(file_path))
      {
        logger_->error("File does not exist: {}", file_path.string());
        return SigstoreError::InvalidTransparencyLog;
      }

    std::ifstream file(file_path, std::ios::in | std::ios::binary);
    if (!file.is_open())
      {
        logger_->error("Failed to open file: {}", file_path.string());
        return SigstoreError::InvalidTransparencyLog;
      }

    std::string json_content;
    try
      {
        json_content.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
      }
    catch (const std::exception &e)
      {
        logger_->error("Error while reading file: {}: {}", file_path.string(), e.what());
        return SigstoreError::InvalidTransparencyLog;
      }

    if (file.bad())
      {
        logger_->error("Error while reading file: {}", file_path.string());
        return SigstoreError::InvalidTransparencyLog;
      }

    return load_from_json(json_content);
  }

  outcome::std_result<OnlineTransparencyLogLoader::TransparencyLogEntryMap> OnlineTransparencyLogLoader::load_from_json(
    const std::string &json_content)
  {
    boost::system::error_code ec;
    boost::json::value parsed = boost::json::parse(json_content, ec);
    if (ec)
      {
        logger_->error("Failed to parse TLog JSON: {}", ec.message());
        return SigstoreError::InvalidTransparencyLog;
      }

    if (!parsed.is_object())
      {
        logger_->error("TLog JSON root is not an object");
        return SigstoreError::InvalidTransparencyLog;
      }

    auto root_object = parsed.as_object();
    TransparencyLogEntryMap result;

    for (const auto &[key, value]: root_object)
      {
        if (!value.is_object())
          {
            logger_->error("Entry with key '{}' must be an object, got: {}", key, boost::json::serialize(value));
            return SigstoreError::InvalidTransparencyLog;
          }

        auto converted_entry = convert_tlog_entry_to_protobuf(value.as_object());
        if (!converted_entry)
          {
            logger_->error("Failed to convert TLog entry with key '{}': {}", key, converted_entry.error().message());
            return converted_entry.error();
          }

        result[std::string(key)] = std::move(converted_entry.value());
      }

    logger_->info("Successfully loaded {} transparency log entries from tlog format", result.size());
    return std::move(result);
  }

  outcome::std_result<OnlineTransparencyLogLoader::TransparencyLogEntryPtr> OnlineTransparencyLogLoader::convert_tlog_entry_to_protobuf(
    const boost::json::object &tlog_obj)
  {
    auto entry = std::make_shared<dev::sigstore::rekor::v1::TransparencyLogEntry>();

    auto result = parse_basic_fields(tlog_obj, entry);
    if (!result)
      {
        return result.error();
      }

    result = parse_kind_version(tlog_obj, entry);
    if (!result)
      {
        return result.error();
      }

    result = parse_verification(tlog_obj, entry);
    if (!result)
      {
        return result.error();
      }

    return std::move(entry);
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_log_index_field(const boost::json::object &tlog_obj,
                                                                               OnlineTransparencyLogLoader::TransparencyLogEntryPtr entry)
  {
    if (const auto *it = tlog_obj.find("logIndex"); it != tlog_obj.end())
      {
        if (it->value().is_int64())
          {
            entry->set_log_index(it->value().as_int64());
          }
        else if (it->value().is_string())
          {
            auto parse_result = parse_int64(std::string(it->value().as_string()));
            if (!parse_result)
              {
                logger_->error("Failed to parse logIndex as integer");
                return SigstoreError::InvalidTransparencyLog;
              }
            entry->set_log_index(parse_result.value());
          }
        else
          {
            logger_->error("logIndex must be an integer or string, got: {}", boost::json::serialize(it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }
    return outcome::success();
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_integrated_time_field(const boost::json::object &tlog_obj,
                                                                                     OnlineTransparencyLogLoader::TransparencyLogEntryPtr entry)
  {
    if (const auto *it = tlog_obj.find("integratedTime"); it != tlog_obj.end())
      {
        if (it->value().is_int64())
          {
            entry->set_integrated_time(it->value().as_int64());
          }
        else if (it->value().is_string())
          {
            auto parse_result = parse_int64(std::string(it->value().as_string()));
            if (!parse_result)
              {
                logger_->error("Failed to parse integratedTime as integer");
                return SigstoreError::InvalidTransparencyLog;
              }
            entry->set_integrated_time(parse_result.value());
          }
        else
          {
            logger_->error("integratedTime must be an integer or string, got: {}", boost::json::serialize(it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }
    return outcome::success();
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_log_id_field(const boost::json::object &tlog_obj,
                                                                            OnlineTransparencyLogLoader::TransparencyLogEntryPtr entry)
  {
    if (const auto *it = tlog_obj.find("logID"); it != tlog_obj.end())
      {
        if (it->value().is_string())
          {
            auto log_id = std::string(it->value().as_string());
            entry->mutable_log_id()->set_key_id(log_id);
          }
        else
          {
            logger_->error("logID must be a string, got: {}", boost::json::serialize(it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }
    return outcome::success();
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_body_field(const boost::json::object &tlog_obj,
                                                                          OnlineTransparencyLogLoader::TransparencyLogEntryPtr entry)
  {
    if (const auto *it = tlog_obj.find("body"); it != tlog_obj.end())
      {
        if (it->value().is_string())
          {
            auto body_b64 = std::string(it->value().as_string());
            auto body_decoded = Base64::decode(body_b64);
            if (!body_decoded.has_value())
              {
                logger_->error("Failed to decode base64 body: {}", body_decoded.error().message());
                return body_decoded.error();
              }
            entry->set_canonicalized_body(body_decoded.value());
          }
        else
          {
            logger_->error("body must be a string, got: {}", boost::json::serialize(it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }
    return outcome::success();
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_basic_fields(const boost::json::object &tlog_obj,
                                                                            OnlineTransparencyLogLoader::TransparencyLogEntryPtr entry)
  {
    auto result = parse_log_index_field(tlog_obj, entry);
    if (!result)
      {
        return result.error();
      }

    result = parse_integrated_time_field(tlog_obj, entry);
    if (!result)
      {
        return result.error();
      }

    result = parse_log_id_field(tlog_obj, entry);
    if (!result)
      {
        return result.error();
      }

    result = parse_body_field(tlog_obj, entry);
    if (!result)
      {
        return result.error();
      }

    return outcome::success();
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_kind_version(const boost::json::object &tlog_obj,
                                                                            OnlineTransparencyLogLoader::TransparencyLogEntryPtr entry)
  {
    if (const auto *it = tlog_obj.find("kindVersion"); it != tlog_obj.end())
      {
        if (!it->value().is_object())
          {
            logger_->error("kindVersion must be an object, got: {}", boost::json::serialize(it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }

        auto kind_version_obj = it->value().as_object();
        auto *kind_version = entry->mutable_kind_version();

        if (const auto *kind_it = kind_version_obj.find("kind"); kind_it != kind_version_obj.end())
          {
            if (kind_it->value().is_string())
              {
                kind_version->set_kind(std::string(kind_it->value().as_string()));
              }
            else
              {
                logger_->error("kindVersion.kind must be a string, got: {}", boost::json::serialize(kind_it->value()));
                return SigstoreError::InvalidTransparencyLog;
              }
          }

        if (const auto *version_it = kind_version_obj.find("version"); version_it != kind_version_obj.end())
          {
            if (version_it->value().is_string())
              {
                kind_version->set_version(std::string(version_it->value().as_string()));
              }
            else
              {
                logger_->error("kindVersion.version must be a string, got: {}", boost::json::serialize(version_it->value()));
                return SigstoreError::InvalidTransparencyLog;
              }
          }
      }

    return outcome::success();
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_verification(const boost::json::object &tlog_obj,
                                                                            OnlineTransparencyLogLoader::TransparencyLogEntryPtr entry)
  {
    if (const auto *it = tlog_obj.find("verification"); it != tlog_obj.end())
      {
        if (!it->value().is_object())
          {
            logger_->error("verification must be an object, got: {}", boost::json::serialize(it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }

        auto verification_obj = it->value().as_object();

        if (auto *proof_it = verification_obj.find("inclusionProof"); proof_it != verification_obj.end())
          {
            if (!proof_it->value().is_object())
              {
                logger_->error("verification.inclusionProof must be an object, got: {}", boost::json::serialize(proof_it->value()));
                return SigstoreError::InvalidTransparencyLog;
              }

            auto proof_obj = proof_it->value().as_object();
            auto *inclusion_proof = entry->mutable_inclusion_proof();

            auto result = parse_inclusion_proof(proof_obj, inclusion_proof);
            if (!result)
              {
                return result.error();
              }
          }

        if (auto *set_it = verification_obj.find("signedEntryTimestamp"); set_it != verification_obj.end())
          {
            if (set_it->value().is_string())
              {
                auto set_str = std::string(set_it->value().as_string());
                entry->mutable_inclusion_promise()->set_signed_entry_timestamp(set_str);
              }
            else
              {
                logger_->error("verification.signedEntryTimestamp must be a string, got: {}", boost::json::serialize(set_it->value()));
                return SigstoreError::InvalidTransparencyLog;
              }
          }
      }

    return outcome::success();
  }

  outcome::std_result<void> OnlineTransparencyLogLoader::parse_inclusion_proof(const boost::json::object &proof_obj,
                                                                               dev::sigstore::rekor::v1::InclusionProof *inclusion_proof)
  {
    if (const auto *log_index_it = proof_obj.find("logIndex"); log_index_it != proof_obj.end())
      {
        if (log_index_it->value().is_int64())
          {
            inclusion_proof->set_log_index(log_index_it->value().as_int64());
          }
        else if (log_index_it->value().is_string())
          {
            auto parse_result = parse_int64(std::string(log_index_it->value().as_string()));
            if (!parse_result)
              {
                logger_->error("Failed to parse inclusion proof logIndex");
                return SigstoreError::InvalidTransparencyLog;
              }
            inclusion_proof->set_log_index(parse_result.value());
          }
        else
          {
            logger_->error("inclusionProof.logIndex must be an integer or string, got: {}", boost::json::serialize(log_index_it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }

    if (const auto *tree_size_it = proof_obj.find("treeSize"); tree_size_it != proof_obj.end())
      {
        if (tree_size_it->value().is_int64())
          {
            inclusion_proof->set_tree_size(tree_size_it->value().as_int64());
          }
        else if (tree_size_it->value().is_string())
          {
            auto parse_result = parse_int64(std::string(tree_size_it->value().as_string()));
            if (!parse_result)
              {
                logger_->error("Failed to parse inclusion proof treeSize");
                return SigstoreError::InvalidTransparencyLog;
              }
            inclusion_proof->set_tree_size(parse_result.value());
          }
        else
          {
            logger_->error("inclusionProof.treeSize must be an integer or string, got: {}", boost::json::serialize(tree_size_it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }

    if (const auto *root_hash_it = proof_obj.find("rootHash"); root_hash_it != proof_obj.end())
      {
        if (root_hash_it->value().is_string())
          {
            inclusion_proof->set_root_hash(std::string(root_hash_it->value().as_string()));
          }
        else
          {
            logger_->error("inclusionProof.rootHash must be a string, got: {}", boost::json::serialize(root_hash_it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }

    if (const auto *hashes_it = proof_obj.find("hashes"); hashes_it != proof_obj.end())
      {
        if (!hashes_it->value().is_array())
          {
            logger_->error("inclusionProof.hashes must be an array, got: {}", boost::json::serialize(hashes_it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }

        auto hashes_array = hashes_it->value().as_array();
        for (const auto &hash_value: hashes_array)
          {
            if (hash_value.is_string())
              {
                inclusion_proof->add_hashes(std::string(hash_value.as_string()));
              }
            else
              {
                logger_->error("inclusionProof.hashes array element must be a string, got: {}", boost::json::serialize(hash_value));
                return SigstoreError::InvalidTransparencyLog;
              }
          }
      }

    if (const auto *checkpoint_it = proof_obj.find("checkpoint"); checkpoint_it != proof_obj.end())
      {
        if (checkpoint_it->value().is_string())
          {
            auto checkpoint_str = std::string(checkpoint_it->value().as_string());
            inclusion_proof->mutable_checkpoint()->set_envelope(checkpoint_str);
          }
        else
          {
            logger_->error("inclusionProof.checkpoint must be a string, got: {}", boost::json::serialize(checkpoint_it->value()));
            return SigstoreError::InvalidTransparencyLog;
          }
      }

    return outcome::success();
  }

} // namespace sigstore
