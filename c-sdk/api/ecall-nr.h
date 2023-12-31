#pragma once

#define ECALL_FATAL            1
#define ECALL_XSEND            2
#define ECALL_XRECV            3
#define ECALL_EXIT             4
#define ECALL_UX_RECTANGLE     5
#define ECALL_SCREEN_UPDATE    6
#define ECALL_BAGL_DRAW_BITMAP 7
#define ECALL_WAIT_BUTTON      8
#define ECALL_BAGL_DRAW        9
#define ECALL_LOADING_START    10
#define ECALL_LOADING_STOP     11
#define ECALL_UX_IDLE          12
#define ECALL_MEMSET           13
#define ECALL_MEMCPY           14
#define ECALL_STRLEN           15
#define ECALL_STRNLEN          16

#define ECALL_DERIVE_NODE_BIP32      100
#define ECALL_CX_ECFP_GENERATE_PAIR  101
#define ECALL_CX_ECFP_ADD_POINT      102
#define ECALL_CX_ECFP_SCALAR_MULT    103
#define ECALL_ECDSA_SIGN             104
#define ECALL_ECDSA_VERIFY           105
#define ECALL_SCHNORR_SIGN           106
#define ECALL_SCHNORR_VERIFY         107
#define ECALL_GET_MASTER_FINGERPRINT 120
#define ECALL_ADDM                   130
#define ECALL_SUBM                   131
#define ECALL_MULTM                  132
#define ECALL_POWM                   133
#define ECALL_HASH_UPDATE            150
#define ECALL_HASH_FINAL             151
#define ECALL_GET_RANDOM_BYTES       160
#define ECALL_CONVERT                170
#define ECALL_TOSTRING256            171
