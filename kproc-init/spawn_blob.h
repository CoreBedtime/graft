#ifndef KPROC_INIT_SPAWN_BLOB_H
#define KPROC_INIT_SPAWN_BLOB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
  KPROC_SPAWN_BLOB_HEADER_SIZE = 240,
};

struct kproc_spawn_blob {
  const uint8_t *base;
  size_t length;
  size_t payload_length;
};

bool kproc_spawn_blob_init(struct kproc_spawn_blob *blob, const void *data, size_t length);
uint8_t kproc_spawn_blob_u8(const struct kproc_spawn_blob *blob, size_t offset);
uint16_t kproc_spawn_blob_u16(const struct kproc_spawn_blob *blob, size_t offset);
uint32_t kproc_spawn_blob_u32(const struct kproc_spawn_blob *blob, size_t offset);
uint64_t kproc_spawn_blob_u64(const struct kproc_spawn_blob *blob, size_t offset);
const void *kproc_spawn_blob_payload(const struct kproc_spawn_blob *blob, uint32_t offset, size_t size);
const char *kproc_spawn_blob_string(const struct kproc_spawn_blob *blob, uint32_t offset);
bool kproc_spawn_blob_strings(const struct kproc_spawn_blob *blob, uint32_t offset, const char **out, size_t count);

#endif
