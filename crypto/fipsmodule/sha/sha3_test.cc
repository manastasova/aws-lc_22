// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <gtest/gtest.h>

#include "../../test/file_test.h"
#include "../../test/test_util.h"
#include "internal.h"
#include <openssl/digest.h>
#include <sys/ioctl.h>


 #include <stdlib.h>
 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <linux/perf_event.h>
 #include <asm/unistd.h>
 #include <sys/syscall.h>


// Add perf linux for benchmarking SHA3/SHAKE
#ifdef __linux__
//#define _GNU_SOURCE //Needed for the perf benchmark measurements
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                       int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
    return ret;
}

static void append_to_file(uint64_t val)
{
    FILE *fp;
    fp = fopen("sha3_shake.txt", "a");
    if (fp == NULL){  
      printf("cannot open file");
      return;
    }
    fprintf(fp, "%lu,\n", val);
    fclose(fp);
}
#endif

static uint64_t gettime() {
#ifdef __aarch64__
  uint64_t ret = 0;
  //uint64_t hz = 0;
  __asm__ __volatile__ ("isb; mrs %0,cntvct_el0":"=r"(ret));
  //__asm__ __volatile__ ("mrs %0,cntfrq_el0; clz %w0, %w0":"=&r"(hz));
  return ret ;
#endif
  return 0;
}

// SHA3TestVector corresponds to one test case of the NIST published file
// SHA3_256ShortMsg.txt.
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
class SHA3TestVector {
 public:
  explicit SHA3TestVector() = default;
  ~SHA3TestVector() = default;

  bool ReadFromFileTest(FileTest *t);
  
  void NISTTestVectors(const EVP_MD *algorithm) const {
    uint32_t digest_length;
    uint8_t *digest  = new uint8_t[EVP_MD_size(algorithm)];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // SHA3 is disabled by default. First test this assumption and then enable SHA3 and test it.
    ASSERT_FALSE(EVP_DigestInit(ctx, algorithm));
    ASSERT_FALSE(EVP_DigestUpdate(ctx, msg_.data(), len_ / 8));
    ASSERT_FALSE(EVP_DigestFinal(ctx, digest, &digest_length));

    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);

    #ifdef __linux__
    //Setup perf to measure time using the high-resolution task counter
    struct perf_event_attr pe;
    uint64_t duration_ns;
    int perf_fd;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_TASK_CLOCK;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    perf_fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (perf_fd == -1) {
    fprintf(stderr, "Error opening leader %llx\n", pe.config);
    return;
    }
    

    //fprintf(stderr, "Pre negotiate wire byte counts: IN=[%lu], OUT=[%lu]\n", conn->wire_bytes_in, conn->wire_bytes_out);
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    // Start of section being measured
    #endif
    uint32_t start, end; 
    start = gettime();
    for (int i = 0; i < 1000; i++) {
    // Test the correctness via the Init, Update and Final Digest APIs.
    ASSERT_TRUE(EVP_DigestInit(ctx, algorithm));
    ASSERT_TRUE(EVP_DigestUpdate(ctx, msg_.data(), len_ / 8));
    ASSERT_TRUE(EVP_DigestFinal(ctx, digest, &digest_length));
    }
    end = gettime();

    #ifdef __linux__
    //// End of section being measured
     ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
     if (!read(perf_fd, &duration_ns, sizeof(duration_ns))){
       return;
     }
     close(perf_fd);
     fprintf(stderr, "gettime() %u vs. perf_event %lu\n", (end - start) / 1000, duration_ns / 1000);
     append_to_file((duration_ns)/1000);
    #endif
    
    ASSERT_EQ(Bytes(digest, EVP_MD_size(algorithm)),
              Bytes(digest_.data(), EVP_MD_size(algorithm)));
 
    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    // Test again SHA3 when |unstable_sha3_enabled_flag| is disabled.
    ASSERT_FALSE(EVP_DigestInit(ctx, algorithm));
    ASSERT_FALSE(EVP_DigestUpdate(ctx, msg_.data(), len_ / 8));
    ASSERT_FALSE(EVP_DigestFinal(ctx, digest, &digest_length));

    delete [] digest;
    OPENSSL_free(ctx);
  }

  void NISTTestVectors_SingleShot(const EVP_MD *algorithm) const {
    uint32_t digest_length;
    uint8_t *digest  = new uint8_t[EVP_MD_size(algorithm)];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    // SHA3 is disabled by default. First test this assumption and then enable SHA3 and test it.
    ASSERT_FALSE(EVP_Digest(msg_.data(), len_ / 8, digest, &digest_length, algorithm, NULL));

    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);

    // Test the correctness via the Single-Shot EVP_Digest APIs.
    ASSERT_TRUE(EVP_Digest(msg_.data(), len_ / 8, digest, &digest_length, algorithm, NULL));
   
    ASSERT_EQ(Bytes(digest, EVP_MD_size(algorithm)),
              Bytes(digest_.data(), EVP_MD_size(algorithm)));

    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    // Test again SHA3 when |unstable_sha3_enabled_flag| is disabled.
    ASSERT_FALSE(EVP_Digest(msg_.data(), len_ / 8, digest, &digest_length, algorithm, NULL));

    delete [] digest;
    OPENSSL_free(ctx);

  }

  void NISTTestVectors_SHAKE128() const {
    uint32_t digest_length = out_len_ / 8;
    uint8_t *digest = new uint8_t[digest_length];

    ASSERT_FALSE(SHAKE128(msg_.data(), msg_.size() , digest, out_len_));

    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);
    
    ASSERT_TRUE(SHAKE128(msg_.data(), msg_.size() , digest, out_len_));
    
    ASSERT_EQ(Bytes(digest, out_len_ / 8),
            Bytes(digest_.data(), out_len_ / 8));

    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    ASSERT_FALSE(SHAKE128(msg_.data(), msg_.size() , digest, out_len_));

    delete [] digest;
  }

  void NISTTestVectors_SHAKE256() const {
    uint32_t digest_length = out_len_ / 8;
    uint8_t *digest = new uint8_t[digest_length];

    ASSERT_FALSE(SHAKE256(msg_.data(), msg_.size() , digest, out_len_));

    // Enable SHA3
    EVP_MD_unstable_sha3_enable(true);
    
    ASSERT_TRUE(SHAKE256(msg_.data(), msg_.size() , digest, out_len_));
    
    ASSERT_EQ(Bytes(digest, out_len_ / 8),
            Bytes(digest_.data(), out_len_ / 8));

    // Disable SHA3
    EVP_MD_unstable_sha3_enable(false);

    ASSERT_FALSE(SHAKE256(msg_.data(), msg_.size() , digest, out_len_));

    delete [] digest;
  }

 private:
  uint16_t len_;
  uint16_t out_len_;
  std::vector<uint8_t> msg_;
  std::vector<uint8_t> digest_;
};

// Read the |key| attribute from |file_test| and convert it to an integer.
template <typename T>
bool FileTestReadInt(FileTest *file_test, T *out, const std::string &key) {
  std::string s;
  return file_test->GetAttribute(&s, key) && 
  testing::internal::ParseInt32(testing::Message() << "The value " << s.data() << \
  " is not convertable to an integer.", s.data(), (int *) out);
}

bool SHA3TestVector::ReadFromFileTest(FileTest *t) {
  if (!t->GetBytes(&msg_, "Msg") ||
      !t->GetBytes(&digest_, "MD")) {
    return false;
  }

  if (t->HasAttribute("Outputlen")) {
    if (!FileTestReadInt(t, &out_len_, "Outputlen")) {
      return false;
    }
  }

  if (t->HasAttribute("Len")) {
    if (!FileTestReadInt(t, &len_, "Len")) {
      return false;
    }
  }

  return true;
}

TEST(SHA3Test, NISTTestVectors) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_224ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_224();
    test_vec.NISTTestVectors(algorithm);
  });
    FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_256ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_384ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_384();
    test_vec.NISTTestVectors(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_512ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors(algorithm);
  });
}

TEST(SHA3Test, NISTTestVectors_SingleShot) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_224ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_224();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_256ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_256();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_384ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_384();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHA3_512ShortMsg.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    const EVP_MD* algorithm = EVP_sha3_512();
    test_vec.NISTTestVectors_SingleShot(algorithm);
  });
}

TEST(SHAKE128Test, NISTTestVectors) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHAKE128VariableOut.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    test_vec.NISTTestVectors_SHAKE128();
  });
}

TEST(SHAKE256Test, NISTTestVectors) {
  FileTestGTest("crypto/fipsmodule/sha/testvectors/SHAKE256VariableOut.txt", [](FileTest *t) {
    SHA3TestVector test_vec;
    EXPECT_TRUE(test_vec.ReadFromFileTest(t));
    test_vec.NISTTestVectors_SHAKE256();
  });
}
