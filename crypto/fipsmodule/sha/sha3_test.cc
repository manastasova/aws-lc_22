// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <gtest/gtest.h>

#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "internal.h"
#include <openssl/digest.h>


// SHA3TestVector corresponds to one test case of the NIST published file
// SHA3_256ShortMsg.txt.
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
class SHA3TestVector {
 public:
  explicit SHA3TestVector() = default;
  ~SHA3TestVector() = default;

  bool ReadFromFileTest(FileTest *t);
  
  void NISTTestVectors(const EVP_MD *algorithm, uint8_t *digest) const {
    uint32_t digest_length;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    #if !defined(OPENSSL_ANDROID)
    // SHA3 is disabled by default. First test this assumption and then enable SHA3 and test it.
    ASSERT_DEATH_IF_SUPPORTED(EVP_DigestInit(ctx, algorithm), "");
    ASSERT_DEATH_IF_SUPPORTED(EVP_DigestUpdate(ctx, msg_.data(), len_ / 8), "");
    ASSERT_DEATH_IF_SUPPORTED(EVP_DigestFinal(ctx, digest, &digest_length), "");
    #endif  // OPENSSL_ANDROID

    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);

    // Test the correctness via the Init, Update and Final Digest APIs.
    ASSERT_TRUE(EVP_DigestInit(ctx, algorithm));
    ASSERT_TRUE(EVP_DigestUpdate(ctx, msg_.data(), len_ / 8));
    ASSERT_TRUE(EVP_DigestFinal(ctx, digest, &digest_length));
    
    ASSERT_EQ(Bytes(digest, SHA3_256_DIGEST_LENGTH),
              Bytes(digest_.data(), SHA3_256_DIGEST_LENGTH));
 
    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    #if !defined(OPENSSL_ANDROID)
    // Test again SHA3 when |unstable_sha3_enabled_flag| is disabled.
    ASSERT_DEATH_IF_SUPPORTED(EVP_DigestInit(ctx, algorithm), "");
    ASSERT_DEATH_IF_SUPPORTED(EVP_DigestUpdate(ctx, msg_.data(), len_ / 8), "");
    ASSERT_DEATH_IF_SUPPORTED(EVP_DigestFinal(ctx, digest, &digest_length), "");
    #endif  // OPENSSL_ANDROID

    OPENSSL_free(ctx);
  }

<<<<<<< HEAD
<<<<<<< HEAD
  void NISTTestVectors_SingleShot(const EVP_MD *algorithm, uint8_t *digest) const {
    uint32_t digest_length;
=======
  void NISTTestVectors_SingleShot() const {
    uint32_t digest_length = SHA3_256_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_256();
    uint8_t digest[SHA3_256_DIGEST_LENGTH];
>>>>>>> 8b06ac629 (Import SHA3 reference implementation from OpenSSL && add EVP structs/functs with TestVector and speed bm (#515))
=======
  void NISTTestVectors_SingleShot(const EVP_MD *algorithm, uint8_t *digest) const {
    uint32_t digest_length;
>>>>>>> fa925c96d (reset --soft)
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    #if !defined(OPENSSL_ANDROID)
    // SHA3 is disabled by default. First test this assumption and then enable SHA3 and test it.
    ASSERT_DEATH_IF_SUPPORTED(EVP_Digest(msg_.data(), len_ / 8, digest, &digest_length, algorithm, NULL), "");
    #endif  // OPENSSL_ANDROID

    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);

    // Test the correctness via the Single-Shot EVP_Digest APIs.
    ASSERT_TRUE(EVP_Digest(msg_.data(), len_ / 8, digest, &digest_length, algorithm, NULL));
   
    ASSERT_EQ(Bytes(digest, SHA3_256_DIGEST_LENGTH),
              Bytes(digest_.data(), SHA3_256_DIGEST_LENGTH));

    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    #if !defined(OPENSSL_ANDROID)
    // Test again SHA3 when |unstable_sha3_enabled_flag| is disabled.
    ASSERT_DEATH_IF_SUPPORTED(EVP_Digest(msg_.data(), len_ / 8, digest, &digest_length, algorithm, NULL), "");
    #endif  // OPENSSL_ANDROID
    
    OPENSSL_free(ctx);

  }

 private:
  uint16_t len_;
  std::vector<uint8_t> msg_;
  std::vector<uint8_t> digest_;
};

// Parses |s| as an unsigned integer of type T and writes the value to |out|.
// Returns true on success. If the integer value exceeds the maximum T value,
// returns false.
template <typename T>
bool ParseIntSafe(T *out, const std::string &s) {
  T value = 0;
  for (char c : s) {
    if (c < '0' || c > '9') {
      return false;
    }
    if (value > (std::numeric_limits<T>::max() - (c - '0')) / 10) {
      return false;
    }
    value = 10 * value + (c - '0');
  }
  *out = value;
  return true;
}

// Read the |key| attribute from |file_test| and convert it to an integer.
template <typename T>
bool FileTestReadInt(FileTest *file_test, T *out, const std::string &key) {
  std::string s;
  return file_test->GetAttribute(&s, key) && ParseIntSafe(out, s);
}

bool SHA3TestVector::ReadFromFileTest(FileTest *t) {
  if (!FileTestReadInt(t, &len_, "Len") ||
      !t->GetBytes(&msg_, "Msg") ||
      !t->GetBytes(&digest_, "MD")) {
    return false;
  }
  return true;
}

TEST(SHA3Test, NISTTestVectors) {
  FileTestGTest("crypto/fipsmodule/sha/SHA3_256ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> fa925c96d (reset --soft)
    uint8_t digest[SHA3_256_DIGEST_LENGTH];
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors(algorithm, digest);
  });
  FileTestGTest("crypto/fipsmodule/sha/SHA3_512ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    uint8_t digest[SHA3_512_DIGEST_LENGTH];
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors(algorithm, digest);
<<<<<<< HEAD
=======
    test_vec.NISTTestVectors();
>>>>>>> 8b06ac629 (Import SHA3 reference implementation from OpenSSL && add EVP structs/functs with TestVector and speed bm (#515))
=======
>>>>>>> fa925c96d (reset --soft)
  });
}

TEST(SHA3Test, NISTTestVectors_SingleShot) {
  FileTestGTest("crypto/fipsmodule/sha/SHA3_256ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> fa925c96d (reset --soft)
    uint8_t digest[SHA3_256_DIGEST_LENGTH];
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors_SingleShot(algorithm, digest);
  });
  FileTestGTest("crypto/fipsmodule/sha/SHA3_512ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    uint8_t digest[SHA3_512_DIGEST_LENGTH];
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors_SingleShot(algorithm, digest);
<<<<<<< HEAD
=======
    test_vec.NISTTestVectors_SingleShot();
>>>>>>> 8b06ac629 (Import SHA3 reference implementation from OpenSSL && add EVP structs/functs with TestVector and speed bm (#515))
=======
>>>>>>> fa925c96d (reset --soft)
  });
}
