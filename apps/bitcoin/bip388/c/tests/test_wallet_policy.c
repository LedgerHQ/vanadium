#include "../include/bip388.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

#define XPUB_A "tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"
#define XPUB_B "tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"

TEST(wp_construction) {
    bip388_key_info_t keys[2] = {0};
    T_EQ_INT(bip388_key_info_parse("[76223a6e/48'/1'/0'/1']" XPUB_A, &keys[0]), BIP388_OK);
    T_EQ_INT(bip388_key_info_parse("[f5acc2fd/48'/1'/0'/1']" XPUB_B, &keys[1]), BIP388_OK);
    bip388_wallet_policy_t wp = {0};
    T_EQ_INT(bip388_wp_new("sh(wsh(sortedmulti(2,@0/**,@1/**)))", keys, 2, &wp), BIP388_OK);
    T_EQ_STR(wp.descriptor_template_raw, "sh(wsh(sortedmulti(2,@0/**,@1/**)))");
    T_EQ_UINT(wp.n_key_information, 2);
    bip388_wp_free(&wp);
    bip388_key_info_free(&keys[0]);
    bip388_key_info_free(&keys[1]);
}

TEST(wp_serialize_roundtrip) {
    bip388_key_info_t keys[2] = {0};
    T_EQ_INT(bip388_key_info_parse("[76223a6e/48'/1'/0'/1']" XPUB_A, &keys[0]), BIP388_OK);
    T_EQ_INT(bip388_key_info_parse(XPUB_B, &keys[1]), BIP388_OK);
    bip388_wallet_policy_t wp = {0};
    T_EQ_INT(bip388_wp_new("sh(wsh(sortedmulti(2,@0/**,@1/**)))", keys, 2, &wp), BIP388_OK);
    uint8_t *buf = NULL;
    size_t len = 0;
    T_EQ_INT(bip388_wp_serialize(&wp, &buf, &len), BIP388_OK);

    bip388_wallet_policy_t wp2 = {0};
    T_EQ_INT(bip388_wp_deserialize(buf, len, &wp2), BIP388_OK);
    T_EQ_STR(wp2.descriptor_template_raw, wp.descriptor_template_raw);
    T_EQ_UINT(wp2.n_key_information, wp.n_key_information);
    T_EQ_UINT(wp2.key_information[0].has_origin, wp.key_information[0].has_origin);
    T_EQ_UINT(wp2.key_information[0].origin.fingerprint, wp.key_information[0].origin.fingerprint);
    T_EQ_UINT(wp2.key_information[0].origin.n_path, wp.key_information[0].origin.n_path);
    for (size_t i = 0; i < wp2.key_information[0].origin.n_path; ++i)
        T_EQ_UINT(wp2.key_information[0].origin.path[i], wp.key_information[0].origin.path[i]);
    T_ASSERT(memcmp(wp2.key_information[0].xpub.raw, wp.key_information[0].xpub.raw, 78) == 0);
    T_ASSERT(memcmp(wp2.key_information[1].xpub.raw, wp.key_information[1].xpub.raw, 78) == 0);

    bip388_free_buf(buf);
    bip388_wp_free(&wp);
    bip388_wp_free(&wp2);
    bip388_key_info_free(&keys[0]);
    bip388_key_info_free(&keys[1]);
}

TEST(wp_deserialize_oversized_descriptor) {
    /* Encode just a VarInt that exceeds the cap. */
    uint8_t buf[16];
    /* varint > 4096: 0xFD then little-endian 2 bytes (4097). */
    buf[0] = 0xFD;
    buf[1] = 0x01;
    buf[2] = 0x10;
    bip388_wallet_policy_t wp = {0};
    T_ASSERT(bip388_wp_deserialize(buf, 3, &wp) != BIP388_OK);
}

TEST(wp_deserialize_oversized_key_count) {
    /* varint 0 (desc len = 0) then varint > MAX_KEYS. */
    uint8_t buf[16];
    size_t pos = 0;
    buf[pos++] = 0x00; /* desc_len = 0 */
    /* MAX_SERIALIZED_KEY_COUNT = 999; 1000 fits in 2 bytes after 0xFD. */
    buf[pos++] = 0xFD;
    buf[pos++] = (uint8_t)(1000 & 0xFF);
    buf[pos++] = (uint8_t)((1000 >> 8) & 0xFF);
    bip388_wallet_policy_t wp = {0};
    T_ASSERT(bip388_wp_deserialize(buf, pos, &wp) != BIP388_OK);
}
