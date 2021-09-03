//
// Created by lamjyoti on 8/25/2021.
//


#include <gtest/gtest.h>
#include "EVP_kem.h"
#include "sike_r3/sike_internal.h"
#include "../include/openssl/mem.h"

TEST(Kem_test, Alloc_and_Free) {

    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char *client_shared_secret = kem_params->shared_secret;
    unsigned char *server_shared_secret = kem_params->shared_secret;

    EXPECT_TRUE(server_shared_secret == client_shared_secret);

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params); //is this needed?
}

TEST(Kem_test, Direct_Calls) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char *client_shared_secret = kem_params->shared_secret;
    unsigned char *server_shared_secret = kem_params->shared_secret;

    // Test a successful round-trip: keygen->enc->dec
    // Test a successful: direct keygen and encap and decap
    EXPECT_TRUE(kem->generate_keypair(kem_params->public_key, kem_params->private_key));
    EXPECT_TRUE(kem->encapsulate(kem_params->ciphertext, kem_params->shared_secret, kem_params->public_key));
    EXPECT_TRUE(kem->decapsulate(kem_params->shared_secret, kem_params->ciphertext, kem_params->private_key));
    EXPECT_TRUE(server_shared_secret == client_shared_secret);

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params); //is this needed?
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

TEST(Kem_test, Basic) {
    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    pq_kem_params *kem_params = (pq_kem_params*)OPENSSL_malloc(sizeof(pq_kem_params));

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char *client_shared_secret = kem_params->shared_secret;
    unsigned char *server_shared_secret = kem_params->shared_secret;

    // Test a successful round-trip: keygen->enc->dec
    EXPECT_TRUE(EVP_kem_generate_keypair(kem_params));
    EXPECT_TRUE(EVP_kem_encapsulate(kem_params));
    EXPECT_TRUE(EVP_kem_decapsulate(kem_params));
    EXPECT_TRUE(server_shared_secret == client_shared_secret);

    // By design, if an invalid private key + ciphertext pair is provided to decapsulate(),
    // the function should still succeed; however, the shared secret that was "decapsulated"
    // will be a garbage random value.

    //kem_params->ciphertext = &kem_params->ciphertext ^ 1; // Flip a bit to invalidate the ciphertext

    EXPECT_TRUE(EVP_kem_decapsulate(kem_params));
    // This test will fail
    EXPECT_FALSE(server_shared_secret == client_shared_secret);

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));
    OPENSSL_free(kem_params); //is this needed?
}
