//
// Created by lamjyoti on 8/25/2021.
//


#include <gtest/gtest.h>
#include "EVP_kem.h"
#include "sike_r3/sike_internal.h"
#include "../include/openssl/mem.h"
#include "../crypto/test/test_util.h"

TEST(Kem_test, Basic_alloc_and_free) {

    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check for successful allocation and free
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));
    EXPECT_TRUE(pq_kem_params_free(kem_params));

    // Clean up
    OPENSSL_free(kem_params);
}

TEST(Kem_test, Baisc_direct_calls) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // Test a successful: direct keygen and encap and decap
    EXPECT_TRUE(kem->generate_keypair(kem_params->public_key, kem_params->private_key));
    EXPECT_TRUE(kem->encapsulate(kem_params->ciphertext, kem_params->shared_secret, kem_params->public_key));
    EXPECT_TRUE(kem->decapsulate(kem_params->shared_secret, kem_params->ciphertext, kem_params->private_key));

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params);
}

TEST(Kem_test, Basic_GenKeyPair) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char *client_shared_secret = kem_params->shared_secret;
    unsigned char *server_shared_secret = kem_params->shared_secret;

    // Test a successful: direct keygen
    EXPECT_TRUE(kem->generate_keypair(kem_params->public_key, kem_params->private_key));
    // Test a successful: API keygen
    EXPECT_TRUE(EVP_kem_generate_keypair(kem_params));
    EXPECT_TRUE(server_shared_secret == client_shared_secret);

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params); //is this needed?
}

TEST(Kem_test, Basic_Encap) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char *client_shared_secret = kem_params->shared_secret;
    unsigned char *server_shared_secret = kem_params->shared_secret;

    // Test a successful: direct keygen and encap
    EXPECT_TRUE(kem->generate_keypair(kem_params->public_key, kem_params->private_key));
    EXPECT_TRUE(kem->encapsulate(kem_params->ciphertext, kem_params->shared_secret, kem_params->public_key));
    // Test a successful: API encap
    EXPECT_TRUE(EVP_kem_encapsulate(kem_params));
    EXPECT_TRUE(server_shared_secret == client_shared_secret);

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params); //is this needed?
}

TEST(Kem_test, Basic_Decap) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char *client_shared_secret = kem_params->shared_secret;
    unsigned char *server_shared_secret = kem_params->shared_secret;

    // Test a successful: direct keygen and encap and decap
    EXPECT_TRUE(kem->generate_keypair(kem_params->public_key, kem_params->private_key));
    EXPECT_TRUE(kem->encapsulate(kem_params->ciphertext, kem_params->shared_secret, kem_params->public_key));
    EXPECT_TRUE(kem->decapsulate(kem_params->shared_secret, kem_params->ciphertext, kem_params->private_key));
    // Test a successful: API decap
    EXPECT_TRUE(EVP_kem_decapsulate(kem_params));
    EXPECT_TRUE(server_shared_secret == client_shared_secret);

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params); //is this needed?
}

TEST(Kem_test, Basic_API_Calls) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // Test a successful round-trip: keygen->enc->dec
    EXPECT_TRUE(EVP_kem_generate_keypair(kem_params));
    EXPECT_TRUE(EVP_kem_encapsulate(kem_params));
    EXPECT_TRUE(EVP_kem_decapsulate(kem_params));

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params);
}

TEST(Kem_test, Basic_Compare_Bytes) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char *client_shared_secret = (unsigned char*)OPENSSL_malloc(sizeof(kem->shared_secret_key_length));
    unsigned char *server_shared_secret = (unsigned char*)OPENSSL_malloc(sizeof(kem->shared_secret_key_length));

    // Test a successful: direct keygen and encap and decap
    EXPECT_TRUE(kem->generate_keypair(kem_params->public_key, kem_params->private_key));
    EXPECT_TRUE(kem->encapsulate(kem_params->ciphertext, client_shared_secret, kem_params->public_key));
    EXPECT_TRUE(kem->decapsulate(server_shared_secret, kem_params->ciphertext, kem_params->private_key));

    EXPECT_EQ(Bytes((const char*) server_shared_secret), Bytes((const char*) client_shared_secret));
    //EXPECT_THAT(server_shared_secret, client_shared_secret);

    // By design, if an invalid private key + ciphertext pair is provided to decapsulate(),
    // the function should still succeed; however, the shared secret that was "decapsulated"
    // will be a garbage random value.

    kem_params->ciphertext[0] ^= 1; // Flip a bit to invalidate the ciphertext

    EXPECT_TRUE(kem->decapsulate(server_shared_secret, kem_params->ciphertext, kem_params->private_key));
    ASSERT_NE(Bytes((const char*) server_shared_secret), Bytes((const char*) client_shared_secret));
    //EXPECT_FALSE(EXPECT_THAT(server_shared_secret, client_shared_secret));

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(client_shared_secret);
    OPENSSL_free(server_shared_secret);
    OPENSSL_free(kem_params);
}
