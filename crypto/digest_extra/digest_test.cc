/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/sha.h>
#include <openssl/sha3.h>

#include "../internal.h"
#include "../test/test_util.h"


struct MD {
  // name is the name of the digest.
  const char* name;
  // md_func is the digest to test.
  const EVP_MD *(*func)(void);
  // one_shot_func is the convenience one-shot version of the
  // digest.
  uint8_t *(*one_shot_func)(const uint8_t *, size_t, uint8_t *);
};

static const MD md4 = { "MD4", &EVP_md4, nullptr };
static const MD md5 = { "MD5", &EVP_md5, &MD5 };
static const MD sha1 = { "SHA1", &EVP_sha1, &SHA1 };
static const MD sha224 = { "SHA224", &EVP_sha224, &SHA224 };
static const MD sha256 = { "SHA256", &EVP_sha256, &SHA256 };
static const MD sha384 = { "SHA384", &EVP_sha384, &SHA384 };
static const MD sha512 = { "SHA512", &EVP_sha512, &SHA512 };
static const MD sha512_256 = { "SHA512-256", &EVP_sha512_256, &SHA512_256 };
static const MD sha3_224 = { "SHA3-224", &EVP_sha3_224, &SHA3_224 };
static const MD sha3_256 = { "SHA3-256", &EVP_sha3_256, &SHA3_256 };
static const MD sha3_384 = { "SHA3-384", &EVP_sha3_384, &SHA3_384 };
static const MD sha3_512 = { "SHA3-512", &EVP_sha3_512, &SHA3_512 };
static const MD md5_sha1 = { "MD5-SHA1", &EVP_md5_sha1, nullptr };
static const MD blake2b256 = { "BLAKE2b-256", &EVP_blake2b256, nullptr };

struct DigestTestVector {
  // md is the digest to test.
  const MD &md;
  // input is a NUL-terminated string to hash.
  const char *input;
  // repeat is the number of times to repeat input.
  size_t repeat;
  // expected_hex is the expected digest in hexadecimal.
  const char *expected_hex;
};

static const DigestTestVector kTestVectors[] = {
    // MD4 tests, from RFC 1320. (crypto/md4 does not provide a
    // one-shot MD4 function.)
    {md4, "", 1, "31d6cfe0d16ae931b73c59d7e0c089c0"},
    {md4, "a", 1, "bde52cb31de33e46245e05fbdbd6fb24"},
    {md4, "abc", 1, "a448017aaf21d8525fc10ae87aa6729d"},
    {md4, "message digest", 1, "d9130a8164549fe818874806e1c7014b"},
    {md4, "abcdefghijklmnopqrstuvwxyz", 1, "d79e1c308aa5bbcdeea8ed63df412da9"},
    {md4, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
     "043f8582f241db351ce627e153e7f0e4"},
    {md4, "1234567890", 8, "e33b4ddc9c38f2199c3e7b164fcc0536"},

    // MD5 tests, from RFC 1321.
    {md5, "", 1, "d41d8cd98f00b204e9800998ecf8427e"},
    {md5, "a", 1, "0cc175b9c0f1b6a831c399e269772661"},
    {md5, "abc", 1, "900150983cd24fb0d6963f7d28e17f72"},
    {md5, "message digest", 1, "f96b697d7cb7938d525a2f31aaf161d0"},
    {md5, "abcdefghijklmnopqrstuvwxyz", 1, "c3fcd3d76192e4007dfb496cca67e13b"},
    {md5, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
     "d174ab98d277d9f5a5611c2c9f419d9f"},
    {md5, "1234567890", 8, "57edf4a22be3c955ac49da2e2107b67a"},

    // SHA-1 tests, from RFC 3174.
    {sha1, "abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d"},
    {sha1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
    {sha1, "a", 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
    {sha1, "0123456701234567012345670123456701234567012345670123456701234567",
     10, "dea356a2cddd90c7a7ecedc5ebb563934f460452"},

    // SHA-224 tests, from RFC 3874.
    {sha224, "abc", 1,
     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
    {sha224, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
    {sha224, "a", 1000000,
     "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"},

    // SHA-256 tests, from NIST.
    {sha256, "abc", 1,
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {sha256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},

    // SHA-384 tests, from NIST.
    {sha384, "abc", 1,
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
     "8086072ba1e7cc2358baeca134c825a7"},
    {sha384,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
     "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     1,
     "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
     "fcc7c71a557e2db966c3e9fa91746039"},

    // SHA-512 tests, from NIST.
    {sha512, "abc", 1,
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {sha512,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
     "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     1,
     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},

    // SHA-512-256 tests, from
    // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha512_256.pdf
    {sha512_256, "abc", 1,
     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
    {sha512_256,
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopj"
     "klmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     1, "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"},

    // SHA3-224 tests checked with
    // https://emn178.github.io/online-tools/sha3_224.html
    {sha3_224, "", 1, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
    {sha3_224, "123", 1, "602bdc204140db016bee5374895e5568ce422fabe17e064061d80097"},
    {sha3_224, "abcdef", 1, "ceb3f4cd85af081120bf69ecf76bf61232bd5d810866f0eca3c8907d"},
    {sha3_224, "a", 1, "9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b"},
    {sha3_224, "abc", 3, "f82797eede9db66a7ba4b52a98ecce4675ff3ad787ca74cb6e14a5ac"},
    {sha3_224, "message digest", 1, "18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8"},
    {sha3_224, "abcdefghijklmnopqrstuvwxyz", 1, "5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239"},
    {sha3_224, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1, "a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e"},
    {sha3_224, "1234567890", 1, "9877af03f5e1919851d0ef4ce6b23f1e85a40b446d93713f4c6e6dcd"},

    // SHA3-256 tests checked with
    // https://emn178.github.io/online-tools/sha3_256.html
    {sha3_256, "", 1, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
    {sha3_256, "123", 1, "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67"},
    {sha3_256, "abcdef", 1, "59890c1d183aa279505750422e6384ccb1499c793872d6f31bb3bcaa4bc9f5a5"},
    {sha3_256, "a", 1, "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"},
    {sha3_256, "abc", 3, "d334a32046b2c342b4e7eb17d7338155c51ef2c12bd5b238667cbb23218982d0"},
    {sha3_256, "message digest", 1, "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd"},
    {sha3_256, "abcdefghijklmnopqrstuvwxyz", 1, "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521"},
    {sha3_256, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1, "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f"},
    {sha3_256, "1234567890", 8, "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d"},
    
    // SHA3-384 tests checked with
    // https://emn178.github.io/online-tools/sha3_384.html
    {sha3_384, "", 1, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
    {sha3_384, "123", 1, "9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007"},
    {sha3_384, "abcdef", 1, "d77460b0ce6109168480e279a81af32facb689ab96e22623f0122ff3a10ead263db6607f83876a843d3264dc2a863805"},
    {sha3_384, "a", 1, "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9"},
    {sha3_384, "abc", 3, "382d39b5f929158b788429fd639381246273b88286add31531d6aa3f44774ed48cd1051805676660c5b00a26a01b5244"},
    {sha3_384, "message digest", 1, "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5"},
    {sha3_384, "abcdefghijklmnopqrstuvwxyz", 1, "fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f"},
    {sha3_384, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1, "d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291"},
    {sha3_384, "1234567890", 1, "6fdddab7d670f202629531c1a51b32ca30696d0af4dd5b0fbb5f82c0aba5e505110455f37d7ef73950c2bb0495a38f56"},

    // SHA3-256 tests checked with
    // https://emn178.github.io/online-tools/sha3_512.html
    {sha3_512, "", 1, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
    {sha3_512, "123", 1, "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc"},
    {sha3_512, "abcdef", 1, "01309a45c57cd7faef9ee6bb95fed29e5e2e0312af12a95fffeee340e5e5948b4652d26ae4b75976a53cc1612141af6e24df36517a61f46a1a05f59cf667046a"},
    {sha3_512, "a", 1, "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a"},
    {sha3_512, "abc", 3, "82734a349a25b5017fbc9208a9fd545b5ea7ab795a1ce00eafd27e1ddbc89378bd6bedb6bbde3d748057c085e14c6f928fd18ea2257b8ab329e16b9cc39a105f"},
    {sha3_512, "message digest", 1, "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59"},
    {sha3_512, "abcdefghijklmnopqrstuvwxyz", 1, "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"},
    {sha3_512, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1, "d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163"},
    {sha3_512, "1234567890",1, "36dde7d288a2166a651d51ec6ded9e70e72cf6b366293d6f513c75393c57d6f33b949879b9d5e7f7c21cd8c02ede75e74fc54ea15bd043b4df008533fc68ae69"},

    // MD5-SHA1 tests.
    {md5_sha1, "abc", 1,
     "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d"},

    // BLAKE2b-256 tests.
    {blake2b256, "abc", 1,
     "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
};

static void CompareDigest(const DigestTestVector *test,
                          const uint8_t *digest,
                          size_t digest_len) {
  EXPECT_EQ(test->expected_hex,
            EncodeHex(bssl::MakeConstSpan(digest, digest_len)));
}

static void TestDigest(const DigestTestVector *test) {
  bssl::ScopedEVP_MD_CTX ctx;

  // Test the input provided.
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
  for (size_t i = 0; i < test->repeat; i++) {
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), test->input, strlen(test->input)));
  }
  std::unique_ptr<uint8_t[]> digest(new uint8_t[EVP_MD_size(test->md.func())]);
  unsigned digest_len;
  ASSERT_TRUE(EVP_DigestFinal_ex(ctx.get(), digest.get(), &digest_len));
  CompareDigest(test, digest.get(), digest_len);

  // Test the input one character at a time.
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
  ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), nullptr, 0));
  for (size_t i = 0; i < test->repeat; i++) {
    for (const char *p = test->input; *p; p++) {
      ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), p, 1));
    }
  }
  ASSERT_TRUE(EVP_DigestFinal_ex(ctx.get(), digest.get(), &digest_len));
  EXPECT_EQ(EVP_MD_size(test->md.func()), digest_len);
  CompareDigest(test, digest.get(), digest_len);

  // Test with unaligned input.
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
  std::vector<char> unaligned(strlen(test->input) + 1);
  char *ptr = unaligned.data();
  if ((reinterpret_cast<uintptr_t>(ptr) & 1) == 0) {
    ptr++;
  }
  OPENSSL_memcpy(ptr, test->input, strlen(test->input));
  for (size_t i = 0; i < test->repeat; i++) {
    ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), ptr, strlen(test->input)));
  }
  ASSERT_TRUE(EVP_DigestFinal_ex(ctx.get(), digest.get(), &digest_len));
  CompareDigest(test, digest.get(), digest_len);

  // Make a copy of the digest in the initial state.
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
  bssl::ScopedEVP_MD_CTX copy;
  ASSERT_TRUE(EVP_MD_CTX_copy_ex(copy.get(), ctx.get()));
  for (size_t i = 0; i < test->repeat; i++) {
    ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
  }
  ASSERT_TRUE(EVP_DigestFinal_ex(copy.get(), digest.get(), &digest_len));
  CompareDigest(test, digest.get(), digest_len);

  // Make a copy of the digest with half the input provided.
  size_t half = strlen(test->input) / 2;
  ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), test->input, half));
  ASSERT_TRUE(EVP_MD_CTX_copy_ex(copy.get(), ctx.get()));
  ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input + half,
                               strlen(test->input) - half));
  for (size_t i = 1; i < test->repeat; i++) {
    ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
  }
  ASSERT_TRUE(EVP_DigestFinal_ex(copy.get(), digest.get(), &digest_len));
  CompareDigest(test, digest.get(), digest_len);

  // Move the digest from the initial state.
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
  copy = std::move(ctx);
  for (size_t i = 0; i < test->repeat; i++) {
    ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
  }
  ASSERT_TRUE(EVP_DigestFinal_ex(copy.get(), digest.get(), &digest_len));
  CompareDigest(test, digest.get(), digest_len);

  // Move the digest with half the input provided.
  ASSERT_TRUE(EVP_DigestInit_ex(ctx.get(), test->md.func(), nullptr));
  ASSERT_TRUE(EVP_DigestUpdate(ctx.get(), test->input, half));
  copy = std::move(ctx);
  ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input + half,
                               strlen(test->input) - half));
  for (size_t i = 1; i < test->repeat; i++) {
    ASSERT_TRUE(EVP_DigestUpdate(copy.get(), test->input, strlen(test->input)));
  }
  ASSERT_TRUE(EVP_DigestFinal_ex(copy.get(), digest.get(), &digest_len));
  CompareDigest(test, digest.get(), digest_len);

  // Test the one-shot function.
  if (test->md.one_shot_func && test->repeat == 1) {
    uint8_t *out = test->md.one_shot_func((const uint8_t *)test->input,
                                          strlen(test->input), digest.get());
    // One-shot functions return their supplied buffers.
    EXPECT_EQ(digest.get(), out);
    CompareDigest(test, digest.get(), EVP_MD_size(test->md.func()));
  }
}

TEST(DigestTest, TestVectors) {
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kTestVectors); i++) {
    SCOPED_TRACE(i);
    TestDigest(&kTestVectors[i]);
  }
}

TEST(DigestTest, Getters) {
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("RSA-SHA512"));
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("sha512WithRSAEncryption"));
  EXPECT_EQ(nullptr, EVP_get_digestbyname("nonsense"));
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("SHA512"));
  EXPECT_EQ(EVP_sha512(), EVP_get_digestbyname("sha512"));

  EXPECT_EQ(EVP_sha512(), EVP_get_digestbynid(NID_sha512));
  EXPECT_EQ(nullptr, EVP_get_digestbynid(NID_sha512WithRSAEncryption));
  EXPECT_EQ(nullptr, EVP_get_digestbynid(NID_undef));

  bssl::UniquePtr<ASN1_OBJECT> obj(OBJ_txt2obj("1.3.14.3.2.26", 0));
  ASSERT_TRUE(obj);
  EXPECT_EQ(EVP_sha1(), EVP_get_digestbyobj(obj.get()));
  EXPECT_EQ(EVP_md5_sha1(), EVP_get_digestbyobj(OBJ_nid2obj(NID_md5_sha1)));
  EXPECT_EQ(EVP_sha1(), EVP_get_digestbyobj(OBJ_nid2obj(NID_sha1)));
}

TEST(DigestTest, ASN1) {
  bssl::ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  EXPECT_FALSE(EVP_marshal_digest_algorithm(cbb.get(), EVP_md5_sha1()));

  static const uint8_t kSHA256[] = {0x30, 0x0d, 0x06, 0x09, 0x60,
                                    0x86, 0x48, 0x01, 0x65, 0x03,
                                    0x04, 0x02, 0x01, 0x05, 0x00};
  static const uint8_t kSHA256NoParam[] = {0x30, 0x0b, 0x06, 0x09, 0x60,
                                           0x86, 0x48, 0x01, 0x65, 0x03,
                                           0x04, 0x02, 0x01};
  static const uint8_t kSHA256GarbageParam[] = {
      0x30, 0x0e, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x02, 0x01, 0x2a};

  // Serialize SHA-256.
  cbb.Reset();
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  ASSERT_TRUE(EVP_marshal_digest_algorithm(cbb.get(), EVP_sha256()));
  uint8_t *der;
  size_t der_len;
  ASSERT_TRUE(CBB_finish(cbb.get(), &der, &der_len));
  bssl::UniquePtr<uint8_t> free_der(der);
  EXPECT_EQ(Bytes(kSHA256), Bytes(der, der_len));

  // Parse SHA-256.
  CBS cbs;
  CBS_init(&cbs, kSHA256, sizeof(kSHA256));
  EXPECT_EQ(EVP_sha256(), EVP_parse_digest_algorithm(&cbs));
  EXPECT_EQ(0u, CBS_len(&cbs));

  // Missing parameters are tolerated for compatibility.
  CBS_init(&cbs, kSHA256NoParam, sizeof(kSHA256NoParam));
  EXPECT_EQ(EVP_sha256(), EVP_parse_digest_algorithm(&cbs));
  EXPECT_EQ(0u, CBS_len(&cbs));

  // Garbage parameters are not.
  CBS_init(&cbs, kSHA256GarbageParam, sizeof(kSHA256GarbageParam));
  EXPECT_FALSE(EVP_parse_digest_algorithm(&cbs));
}

TEST(DigestTest, TransformBlocks) {
  uint8_t blocks[SHA256_CBLOCK * 10];
  for (size_t i = 0; i < sizeof(blocks); i++) {
    blocks[i] = i*3;
  }

  SHA256_CTX ctx1;
  SHA256_Init(&ctx1);
  SHA256_Update(&ctx1, blocks, sizeof(blocks));

  SHA256_CTX ctx2;
  SHA256_Init(&ctx2);
  SHA256_TransformBlocks(ctx2.h, blocks, sizeof(blocks) / SHA256_CBLOCK);

  EXPECT_TRUE(0 == OPENSSL_memcmp(ctx1.h, ctx2.h, sizeof(ctx1.h)));
}
