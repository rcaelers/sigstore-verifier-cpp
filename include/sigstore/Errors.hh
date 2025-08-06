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

#ifndef CONTEXT_ERRORS_HH
#define CONTEXT_ERRORS_HH

#include <system_error>

namespace sigstore
{
  enum class SigstoreError
  {
    InvalidBundle = 1,
    InvalidSignature,
    InvalidCertificate,
    InvalidPublicKey,
    InvalidTransparencyLog,
    InvalidContext,
    JsonParseError,
    SystemError,
    InvalidBase64,
  };

  class SigstoreErrorCategory : public std::error_category
  {
  public:
    const char *name() const noexcept override
    {
      return "sigstore";
    }

    std::string message(int ev) const override
    {
      switch (static_cast<SigstoreError>(ev))
        {
        case SigstoreError::InvalidBundle:
          return "Invalid bundle";
        case SigstoreError::InvalidSignature:
          return "Invalid signature";
        case SigstoreError::InvalidCertificate:
          return "Invalid certificate";
        case SigstoreError::InvalidPublicKey:
          return "Invalid public key";
        case SigstoreError::InvalidTransparencyLog:
          return "Invalid transparency log";
        case SigstoreError::InvalidContext:
          return "Invalid context";
        case SigstoreError::JsonParseError:
          return "JSON parse error";
        case SigstoreError::SystemError:
          return "System error";
        case SigstoreError::InvalidBase64:
          return "Invalid Base64";
        default:
          return "Unknown error";
        }
    }
  };

  const std::error_category &context_error_category();
  std::error_code make_error_code(SigstoreError e);

} // namespace sigstore

namespace std
{
  template<>
  struct is_error_code_enum<sigstore::SigstoreError> : std::true_type
  {
  };
} // namespace std

#endif
