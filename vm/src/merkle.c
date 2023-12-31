#include <limits.h>
#include <string.h>

#include "merkle.h"

#include "cx.h"

static struct merkle_tree_ctx_s ctx;
static cx_sha256_t hash_ctx;

static void hash_entry(const struct entry_s *entry, uint8_t *hash)
{
    cx_sha256_init_no_throw(&hash_ctx);

    cx_hash_no_throw((cx_hash_t *)&hash_ctx, 0, (uint8_t *)"\x00", 1, NULL, 0);
    cx_hash_no_throw((cx_hash_t *)&hash_ctx, CX_LAST, (uint8_t *)entry, sizeof(*entry), hash,
                     CX_SHA256_SIZE);
}

static void hash_nodes(const uint8_t *left, const uint8_t *right, uint8_t *hash)
{
    cx_sha256_init_no_throw(&hash_ctx);

    cx_hash_no_throw((cx_hash_t *)&hash_ctx, 0, (uint8_t *)"\x01", sizeof(uint8_t), NULL, 0);
    cx_hash_no_throw((cx_hash_t *)&hash_ctx, 0, left, CX_SHA256_SIZE, NULL, 0);
    cx_hash_no_throw((cx_hash_t *)&hash_ctx, CX_LAST, right, CX_SHA256_SIZE, hash, CX_SHA256_SIZE);
}

static void proof_hash(const struct entry_s *entry,
                       const struct proof_s *proof,
                       size_t count,
                       uint8_t *digest)
{
    if (entry != NULL) {
        hash_entry(entry, digest);
    }

    for (size_t i = 0; i < count; i++) {
        const uint8_t *left, *right;

        if (proof->op == 'L') {
            left = proof->digest;
            right = digest;
        } else {
            left = digest;
            right = proof->digest;
        }

        hash_nodes(left, right, digest);

        proof++;
    }
}

static size_t bit_count(uint32_t x)
{
    size_t count = 0;

    while (x) {
        count += x & 1;
        x >>= 1;
    }

    return count;
}

bool merkle_insert(const struct entry_s *entry, const struct proof_s *proof, size_t count)
{
    if (ctx.n == 0) {
        hash_entry(entry, ctx.root_hash);
        memcpy(&ctx.last_entry, entry, sizeof(*entry));
        ctx.n++;
        return true;
    } else if (ctx.n == ULONG_MAX) {
        /* the merkle tree size will overflow */
        return false;
    }

    struct proof_s tmp_proof;
    size_t tree_level = count - (bit_count(ctx.n) - 1);

    /* check against integer overflow */
    if (tree_level > count) {
        return false;
    }

    proof_hash(&ctx.last_entry, proof, count, tmp_proof.digest);
    if (memcmp(tmp_proof.digest, ctx.root_hash, sizeof(ctx.root_hash)) != 0) {
        return false;
    }

    tmp_proof.op = 'L';
    proof_hash(&ctx.last_entry, proof, tree_level, tmp_proof.digest);

    /* compute new root hash */
    proof_hash(entry, &tmp_proof, 1, ctx.root_hash);
    proof_hash(NULL, proof + tree_level, count - tree_level, ctx.root_hash);

    memcpy(&ctx.last_entry, entry, sizeof(*entry));
    ctx.n++;

    return true;
}

bool merkle_update(const struct entry_s *old_entry,
                   const struct entry_s *entry,
                   const struct proof_s *proof,
                   size_t count)
{
    if (!merkle_verify_proof(old_entry, proof, count)) {
        return false;
    }

    proof_hash(entry, proof, count, ctx.root_hash);

    /* update last entry if required */
    if (memcmp(&ctx.last_entry, old_entry, sizeof(ctx.last_entry)) == 0) {
        memcpy(&ctx.last_entry, entry, sizeof(ctx.last_entry));
    }

    return true;
}

bool merkle_verify_proof(const struct entry_s *entry, const struct proof_s *proof, size_t count)
{
    uint8_t digest[CX_SHA256_SIZE];

    proof_hash(entry, proof, count, digest);

    return memcmp(digest, ctx.root_hash, sizeof(ctx.root_hash)) == 0;
}

void init_merkle_tree(const uint8_t *root_hash_init,
                      size_t merkle_tree_size,
                      const struct entry_s *last_entry_init)
{
    memcpy(ctx.root_hash, root_hash_init, sizeof(ctx.root_hash));
    memcpy(&ctx.last_entry, last_entry_init, sizeof(ctx.last_entry));
    ctx.n = merkle_tree_size;
}
