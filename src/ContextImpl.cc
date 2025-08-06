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

#include "ContextImpl.hh"

#include <memory>
#include <string>
#include <boost/outcome.hpp>
#include <spdlog/spdlog.h>

#include "CertificateStore.hh"
#include "embedded_trust_bundle.h"

namespace outcome = boost::outcome_v2;

namespace sigstore
{
  ContextImpl::ContextImpl()
    : certificate_store_(std::make_shared<CertificateStore>())
  {
  }

  ContextImpl::~ContextImpl() = default;

  outcome::std_result<void> ContextImpl::load_embedded_fulcio_ca_certificates()
  {
    logger_->debug("Loading embedded Fulcio CA certificates using CertificateStore");

    std::string trust_bundle_json{embedded_trust_bundle};

    auto certificate_store_res = certificate_store_->load_trust_bundle(trust_bundle_json);
    if (!certificate_store_res)
      {
        logger_->error("Failed to load embedded Fulcio CA certificates: {}", certificate_store_res.error().message());
        return certificate_store_res.error();
      }

    return outcome::success();
  }

  outcome::std_result<void> ContextImpl::add_ca_certificate(const std::string &ca_certificate)
  {
    logger_->debug("Adding CA certificates to CertificateStore");

    auto result = certificate_store_->add_ca_certificates(ca_certificate);
    if (!result)
      {
        logger_->error("Failed to add CA certificates: {}", result.error().message());
        return result.error();
      }

    return outcome::success();
  }

  std::shared_ptr<CertificateStore> ContextImpl::get_certificate_store() const
  {
    return certificate_store_;
  }

} // namespace sigstore
