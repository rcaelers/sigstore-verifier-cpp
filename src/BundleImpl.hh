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

#ifndef BUNDLE_IMPL_HH
#define BUNDLE_IMPL_HH

#include <memory>
#include <optional>
#include <string_view>
#include <boost/outcome/std_result.hpp>
#include <spdlog/spdlog.h>

#include "Certificate.hh"
#include "ContextImpl.hh"
#include "Logging.hh"
#include "sigstore/Bundle.hh"
#include "sigstore_bundle.pb.h"

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  class SigstoreContext;

  class BundleImpl : public Bundle
  {
  public:
    explicit BundleImpl(std::shared_ptr<ContextImpl> context, dev::sigstore::bundle::v1::Bundle internal_bundle);
    ~BundleImpl() override = default;

    static std::shared_ptr<BundleImpl> create(std::shared_ptr<ContextImpl> context, const dev::sigstore::bundle::v1::Bundle &bundle);
    static outcome::std_result<std::shared_ptr<Bundle>> create(std::shared_ptr<ContextImpl> context, std::string_view bundle_json);

    std::shared_ptr<CertificateInfo> get_certificate_info() const override;
    const dev::sigstore::bundle::v1::Bundle &get_bundle() const override;

    outcome::std_result<void> verify(const std::string_view &data) override;
    outcome::std_result<void> verify_signature(const std::string_view &data) const override;
    outcome::std_result<void> verify_transparency_log_offline() const override;

    std::shared_ptr<Certificate> get_certificate() const;
    std::string get_signature() const;
    std::optional<std::string> get_message_digest() const;
    std::optional<std::string> get_algorithm() const;
    int64_t get_log_index() const;
    const ::google::protobuf::RepeatedPtrField<::dev::sigstore::rekor::v1::TransparencyLogEntry> &get_transparency_log_entries() const;

  private:
    std::shared_ptr<Certificate> extract_certificate() const;
    std::string extract_signature() const;
    std::optional<std::string> extract_message_digest() const;
    std::optional<std::string> extract_algorithm() const;
    int64_t extract_log_index() const;

  private:
    std::shared_ptr<spdlog::logger> logger_{Logging::create("sigstore:bundle_loader")};
    std::shared_ptr<ContextImpl> context_;
    dev::sigstore::bundle::v1::Bundle internal_bundle_;
    mutable std::shared_ptr<Certificate> certificate_;
  };

} // namespace sigstore

#endif // BUNDLE_IMPL_HH
