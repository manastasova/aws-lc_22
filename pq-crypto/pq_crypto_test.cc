//
// Created by lamjyoti on 8/25/2021.
//


#include <gtest/gtest.h>
#include "EVP_kem.h"
#include "sike_r3/sike_internal.h"


TEST(Kem_test, Basic) {

    // Initialize sike kem and kem_params
    const struct pq_kem *kem = &evp_sike_p434_r3;
    const struct pq_kem_params *kem_params;

    // check allocation successful
    ASSERT_TRUE(pq_kem_params_alloc(kem, kem_params));

    // track shared secrets
    unsigned char client_shared_secret = kem_params->shared_secret;
    unsigned char server_shared_secret = kem_params->shared_secret;

    // Test a successful round-trip: keygen->enc->dec
    EXPECT_TRUE(EVP_kem_generate_keypair(kem_params));
    EXPECT_TRUE(EVP_kem_encapsulate(kem_params));
    EXPECT_TRUE(EVP_kem_decapsulate(kem_params));
    ASSERT_THAT(server_shared_secret, client_shared_secret);

    // By design, if an invalid private key + ciphertext pair is provided to decapsulate(),
    // the function should still succeed (return S2N_SUCCESS); however, the shared secret
    // that was "decapsulated" will be a garbage random value. s2n_bike1_l1_r1 is an
    // exception which does not satisfy this property.

    kem_params->ciphertext ^= 1; // Flip a bit to invalidate the ciphertext

    EXPECT_TRUE(EVP_kem_decapsulate(kem_params));
    ASSERT_FALSE(ASSERT_THAT(server_shared_secret, client_shared_secret));

    // Clean up
    EXPECT_TRUE(pq_kem_params_free(kem_params));

}

