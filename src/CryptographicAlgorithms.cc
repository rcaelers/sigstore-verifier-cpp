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

#include "CryptographicAlgorithms.hh"
#include "sigstore/SigstoreErrors.hh"

namespace sigstore
{
  outcome::std_result<DigestAlgorithm> digest_algorithm_from_string(const std::string &algorithm_name)
  {
    if (algorithm_name == "sha1")
      {
        return DigestAlgorithm::SHA1;
      }
    if (algorithm_name == "sha256")
      {
        return DigestAlgorithm::SHA256;
      }
    if (algorithm_name == "sha384")
      {
        return DigestAlgorithm::SHA384;
      }
    if (algorithm_name == "sha512")
      {
        return DigestAlgorithm::SHA512;
      }

    return SigstoreError::InvalidSignature;
  }

} // namespace sigstore
