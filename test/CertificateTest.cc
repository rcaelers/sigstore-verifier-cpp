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

#include "Certificate.hh"
#include "CryptographicAlgorithms.hh"
#include "Base64.hh"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace sigstore::test
{
  class CertificateTest : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
    }
  };

  TEST_F(CertificateTest, ParseInvalidCertificate)
  {
    const std::string invalid_cert = "invalid certificate data";

    auto cert = Certificate::from_pem(invalid_cert);

    EXPECT_FALSE(cert);
  }

  TEST_F(CertificateTest, VerifyCertificateChainWithoutTrustBundle)
  {
    const std::string cert_pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";

    auto cert = Certificate::from_pem(cert_pem);
    EXPECT_FALSE(cert);
  }

  TEST_F(CertificateTest, VerifyCertificateChainWithTrustBundle)
  {
    auto cert = Certificate::from_pem(Base64::decode(
      "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWxxZ0F3SUJBZ0lVWUZQRk11MGNueWZPSHBNNm1SZUdtWVh2MGEwd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpVd056QTVNVGd3TWpRMldoY05NalV3TnpBNU1UZ3hNalEyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYcXNHWVJaMUo4SHptclhqMVlRZ0ltQ2I5SUQ5U0xPd01QZjQKM1pORXFaOVg3aVMxSFd2WjQ2MThoNVFqSk5qbjcxMHFjWmFRWTVlTXVOamV2cFc5V2FPQ0FYa3dnZ0YxTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVV2RnlwClZxbDBrL25CRk1xY3Q4UHFxbFhlT2NFd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0l3WURWUjBSQVFIL0JCa3dGNEVWY205aUxtTmhaV3hsY25OQVoyMWhhV3d1WTI5dE1Dd0dDaXNHQVFRQgpnNzh3QVFFRUhtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOXNiMmRwYmk5dllYVjBhREF1QmdvckJnRUVBWU8vCk1BRUlCQ0FNSG1oMGRIQnpPaTh2WjJsMGFIVmlMbU52YlM5c2IyZHBiaTl2WVhWMGFEQ0JpZ1lLS3dZQkJBSFcKZVFJRUFnUjhCSG9BZUFCMkFOMDlNR3JHeHhFeVl4a2VISmxuTndLaVNsNjQzanl0LzRlS2NvQXZLZTZPQUFBQgpsL0JhdHVFQUFBUURBRWN3UlFJZ0hmVFdxRXROaUtKZElQM0hseDNqZnBUbEU1RUtMcnpRYURyOFhOb2QvbDhDCklRQ080MUxyeTBFMFJnQ2sxMk5qelhMZ0kzZlg5MElNYmpZT0NpN3FwSjFwb2pBS0JnZ3Foa2pPUFFRREF3Tm4KQURCa0FqQkR4dEN6TUJpOXVHYVlmbEZrbGtIYjlnYUkxQWVwU3k5RHhSdUllZ2RzTG52dEhOZDNyTHdiZlBxSgpaT3c0QjRRQ01CNDFvQytPMWhPMTVxaTFMdFFWQm16a1hMdFdJeTZ5b3VIUjFrc0pDTVk5aW1OV1ZlK3BVSlFNCi80bHh2ajcvcWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==").value());
    EXPECT_TRUE(cert);
    EXPECT_EQ(cert->oidc_issuer(), "https://github.com/login/oauth");
    EXPECT_EQ(cert->subject_email(), "rob.caelers@gmail.com");
    EXPECT_FALSE(cert->is_self_signed());
  }

  TEST_F(CertificateTest, ParseCertificateFromDER)
  {
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";

    auto cert_der_string = Base64::decode(cert_der_base64).value();
    std::vector<uint8_t> cert_der_data(cert_der_string.begin(), cert_der_string.end());
    auto cert = Certificate::from_der(cert_der_data);

    EXPECT_TRUE(cert);
    EXPECT_EQ(cert->oidc_issuer(), "https://github.com/login/oauth");
    EXPECT_EQ(cert->subject_email(), "rob.caelers@gmail.com");
    EXPECT_FALSE(cert->is_self_signed());
  }

  TEST_F(CertificateTest, ParseInvalidCertificateFromDER)
  {
    const std::vector<uint8_t> invalid_cert_der = {0x00, 0x01, 0x02, 0x03};

    auto cert = Certificate::from_der(invalid_cert_der);

    EXPECT_FALSE(cert);
  }

  TEST_F(CertificateTest, ParseCertificateFromDERString)
  {
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";

    auto cert_der_string = Base64::decode(cert_der_base64).value();
    auto cert = Certificate::from_der(cert_der_string);

    EXPECT_TRUE(cert);
    EXPECT_EQ(cert->oidc_issuer(), "https://github.com/login/oauth");
    EXPECT_EQ(cert->subject_email(), "rob.caelers@gmail.com");
    EXPECT_FALSE(cert->is_self_signed());
  }

  TEST_F(CertificateTest, VerifySignatureMethodExists)
  {
    // Test that the new verify_signature methods exist and can be called
    // We don't have real signature data, so we test with empty data to verify the API
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";

    auto cert_der_string = Base64::decode(cert_der_base64).value();
    auto cert = Certificate::from_der(cert_der_string);

    ASSERT_TRUE(cert);

    // Test vector<uint8_t> version with empty data (should fail but not crash)
    std::vector<uint8_t> empty_data;
    std::vector<uint8_t> empty_signature;
    auto result1 = cert->verify_signature(empty_data, empty_signature);
    EXPECT_FALSE(result1.has_value()); // Should return an error for invalid signature

    // Test string version with empty data (should fail but not crash)
    std::string empty_data_str;
    std::string empty_signature_str;
    auto result2 = cert->verify_signature(empty_data_str, empty_signature_str);
    EXPECT_FALSE(result2.has_value()); // Should return an error for invalid signature

    // Test with different digest algorithms
    auto result3 = cert->verify_signature(empty_data, empty_signature, DigestAlgorithm::SHA384);
    EXPECT_FALSE(result3.has_value());
  }

  TEST_F(CertificateTest, CertificateComparison)
  {
    // Test certificate created from DER
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";
    auto cert_der_string = Base64::decode(cert_der_base64).value();

    // Create first certificate from DER
    auto cert1 = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert1);

    // Create second certificate from DER (same data)
    auto cert2 = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert2);

    // Test equality
    EXPECT_TRUE(*cert1 == *cert2);
    EXPECT_FALSE(*cert1 != *cert2);
  }

  // =============================================================================
  // Key Usage Verification Tests
  // =============================================================================

  TEST_F(CertificateTest, VerifyKeyUsage_ValidCertificate)
  {
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";
    auto cert_der_string = Base64::decode(cert_der_base64).value();
    auto cert = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert);

    auto result = cert->verify_key_usage();
    EXPECT_TRUE(result.has_value()) << "Expected valid key usage verification to succeed";
  }

  TEST_F(CertificateTest, VerifyKeyUsage_NullCertificate)
  {
    std::string invalid_cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBIDCC not valid\n-----END CERTIFICATE-----";
    auto cert = Certificate::from_pem(invalid_cert_pem);
    EXPECT_FALSE(cert);
  }

  TEST_F(CertificateTest, VerifyKeyUsage_NoExtendedKeyUsage)
  {
    const std::string cert_no_eku_der =
      "MIIBrjCCAVWgAwIBAgIUZ33mU5MXk4+CKFinKK1XyLKs/O4wCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLVGVzdCBObyBFS1UwHhcNMjUwNzMxMTM0MTEwWhcNMjYwNzMxMTM0MTEwWjAWMRQwEgYDVQQDDAtUZXN0IE5vIEVLVTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJH1vUJ1Xmdm8jRF68lqmWckRn2B4FBPdrq08QD4XXQsVW0hNltNAyWW3S+mTKaaqoGJvsl5iOwwR/iKbb4NMXKjgYAwfjAdBgNVHQ4EFgQUkiXlEtrPq0svl3lfVcarWSGjVSAwHwYDVR0jBBgwFoAUkiXlEtrPq0svl3lfVcarWSGjVSAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCB4AwGwYDVR0RBBQwEoEQdGVzdEBleGFtcGxlLmNvbTAKBggqhkjOPQQDAgNHADBEAiBkUEsQO7BOhT9tX4+lwz15DnryczAP1Gy8d6yqomj90QIgA42ePbJ8rO57FbqbxfX5qYsl9zv9E0SZtAw+BP2fSHM=";
    auto cert_der_string = Base64::decode(cert_no_eku_der).value();
    auto cert = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert);

    auto result = cert->verify_key_usage();
    EXPECT_FALSE(result.has_value()) << "Expected certificate without EKU to fail verification";
  }

  TEST_F(CertificateTest, VerifyKeyUsage_NoCodeSigning)
  {
    const std::string cert_no_code_signing_der =
      "MIIB1zCCAX2gAwIBAgIUdV6QzURMfp8ENsdr5KVBPkTr6n0wCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUVGVzdCBObyBDb2RlIFNpZ25pbmcwHhcNMjUwNzMxMTM0MTI4WhcNMjYwNzMxMTM0MTI4WjAfMR0wGwYDVQQDDBRUZXN0IE5vIENvZGUgU2lnbmluZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJH1vUJ1Xmdm8jRF68lqmWckRn2B4FBPdrq08QD4XXQsVW0hNltNAyWW3S+mTKaaqoGJvsl5iOwwR/iKbb4NMXKjgZYwgZMwHQYDVR0OBBYEFJIl5RLaz6tLL5d5X1XGq1kho1UgMB8GA1UdIwQYMBaAFJIl5RLaz6tLL5d5X1XGq1kho1UgMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMBsGA1UdEQQUMBKBEHRlc3RAZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgOw5XeLA6sIb3/0QyMn0Bdy95eJjFeN22bIuGgZRpaqoCIQDVVGFK+yxCsmm1sapjFBe9MimyufAk52uqa+vw6Qfntw==";
    auto cert_der_string = Base64::decode(cert_no_code_signing_der).value();
    auto cert = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert);

    auto result = cert->verify_key_usage();
    EXPECT_FALSE(result.has_value()) << "Expected certificate without Code Signing EKU to fail verification";
  }

  TEST_F(CertificateTest, VerifyKeyUsage_ValidCodeSigning)
  {
    const std::string cert_valid_der =
      "MIIBwzCCAWmgAwIBAgIUFFZ6ZISyFiaaulkPOVl/TEAJA4AwCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwKVGVzdCBWYWxpZDAeFw0yNTA3MzExMzQxNDNaFw0yNjA3MzExMzQxNDNaMBUxEzARBgNVBAMMClRlc3QgVmFsaWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASR9b1CdV5nZvI0RevJaplnJEZ9geBQT3a6tPEA+F10LFVtITZbTQMllt0vpkymmqqBib7JeYjsMEf4im2+DTFyo4GWMIGTMB0GA1UdDgQWBBSSJeUS2s+rSy+XeV9VxqtZIaNVIDAfBgNVHSMEGDAWgBSSJeUS2s+rSy+XeV9VxqtZIaNVIDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgNVHREEFDASgRB0ZXN0QGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIQD5VIWCFlEIdWmtzpxC4PRPDV+hIDJLf2UtLqlgboSW5QIgXpC9UTRZX+AofdhZo99zuwQ983rCPWwDdDtLeAppWWo=";
    auto cert_der_string = Base64::decode(cert_valid_der).value();
    auto cert = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert);

    auto result = cert->verify_key_usage();
    EXPECT_TRUE(result.has_value()) << "Expected valid certificate with Code Signing to pass verification";
  }

  TEST_F(CertificateTest, VerifyKeyUsage_CodeSigningNoKeyUsage)
  {
    const std::string cert_no_key_usage_der =
      "MIIBwDCCAWegAwIBAgIUGrxjlGGov2EwOEXqq3n5KqLVQNgwCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRVGVzdCBObyBLZXkgVXNhZ2UwHhcNMjUwNzMxMTM0MjAyWhcNMjYwNzMxMTM0MjAyWjAcMRowGAYDVQQDDBFUZXN0IE5vIEtleSBVc2FnZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJH1vUJ1Xmdm8jRF68lqmWckRn2B4FBPdrq08QD4XXQsVW0hNltNAyWW3S+mTKaaqoGJvsl5iOwwR/iKbb4NMXKjgYYwgYMwHQYDVR0OBBYEFJIl5RLaz6tLL5d5X1XGq1kho1UgMB8GA1UdIwQYMBaAFJIl5RLaz6tLL5d5X1XGq1kho1UgMA8GA1UdEwEB/wQFMAMBAf8wEwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0RBBQwEoEQdGVzdEBleGFtcGxlLmNvbTAKBggqhkjOPQQDAgNHADBEAiByYJWIuWGPfOx7w0+yjpY+kwAuoMGs1tQeKMfX/bwczwIgKc3VcR14aE57kaXlYqKnCCkArfTqQkcmPLKsYtDBsDA=";
    auto cert_der_string = Base64::decode(cert_no_key_usage_der).value();
    auto cert = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert);

    auto result = cert->verify_key_usage();
    EXPECT_TRUE(result.has_value()) << "Expected certificate with Code Signing EKU but no Key Usage to pass verification";
  }

  TEST_F(CertificateTest, VerifyKeyUsage_NoDigitalSignature)
  {
    const std::string cert_no_digital_sig_der =
      "MIIB1TCCAXugAwIBAgIUM4x4C7wX7bs1suowoiaYipOourYwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTVGVzdCBObyBEaWdpdGFsIFNpZzAeFw0yNTA3MzExMzQzMjFaFw0yNjA3MzExMzQzMjFaMB4xHDAaBgNVBAMME1Rlc3QgTm8gRGlnaXRhbCBTaWcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASR9b1CdV5nZvI0RevJaplnJEZ9geBQT3a6tPEA+F10LFVtITZbTQMllt0vpkymmqqBib7JeYjsMEf4im2+DTFyo4GWMIGTMB0GA1UdDgQWBBSSJeUS2s+rSy+XeV9VxqtZIaNVIDAfBgNVHSMEGDAWgBSSJeUS2s+rSy+XeV9VxqtZIaNVIDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIFIDATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgNVHREEFDASgRB0ZXN0QGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIG+Yd+khPCObzXeG5p4mvRvsjuUx+ZfXcuJOz768Ae9tAiEArDLtexMfPEx15TT4H453n3LpyUhZChs7yRi7czIN+P4=";
    auto cert_der_string = Base64::decode(cert_no_digital_sig_der).value();
    auto cert = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert);

    auto result = cert->verify_key_usage();
    EXPECT_TRUE(result.has_value()) << "Expected certificate with Code Signing EKU but no Digital Signature KU to pass verification (with warning)";
  }

  TEST_F(CertificateTest, VerifyKeyUsage_ExistingValidCertificate)
  {
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";
    auto cert_der_string = Base64::decode(cert_der_base64).value();
    auto cert = Certificate::from_der(cert_der_string);
    ASSERT_TRUE(cert);

    auto result = cert->verify_key_usage();
    EXPECT_TRUE(result.has_value()) << "Expected real sigstore certificate to pass key usage verification";
  }

} // namespace sigstore::test
