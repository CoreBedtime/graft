#include "spawn_blob.h"

#include <string.h>

bool
kproc_spawn_blob_init(struct kproc_spawn_blob *blob, const void *data, size_t length)
{
  if (data == NULL || length < KPROC_SPAWN_BLOB_HEADER_SIZE) {
    return false;
  }

  blob->base = data;
  blob->length = length;
  blob->payload_length = length - KPROC_SPAWN_BLOB_HEADER_SIZE;
  return true;
}

static bool
read_field(const struct kproc_spawn_blob *blob, size_t offset, void *out, size_t size)
{
  if (offset > blob->length || size > blob->length - offset) {
    memset(out, 0, size);
    return false;
  }

  memcpy(out, blob->base + offset, size);
  return true;
}

uint8_t
kproc_spawn_blob_u8(const struct kproc_spawn_blob *blob, size_t offset)
{
  uint8_t value = 0;
  (void) read_field(blob, offset, &value, sizeof(value));
  return value;
}

uint16_t
kproc_spawn_blob_u16(const struct kproc_spawn_blob *blob, size_t offset)
{
  uint16_t value = 0;
  (void) read_field(blob, offset, &value, sizeof(value));
  return value;
}

uint32_t
kproc_spawn_blob_u32(const struct kproc_spawn_blob *blob, size_t offset)
{
  uint32_t value = 0;
  (void) read_field(blob, offset, &value, sizeof(value));
  return value;
}

uint64_t
kproc_spawn_blob_u64(const struct kproc_spawn_blob *blob, size_t offset)
{
  uint64_t value = 0;
  (void) read_field(blob, offset, &value, sizeof(value));
  return value;
}

const void *
kproc_spawn_blob_payload(const struct kproc_spawn_blob *blob, uint32_t offset, size_t size)
{
  if (offset > blob->payload_length || size > blob->payload_length - offset) {
    return NULL;
  }

  return blob->base + KPROC_SPAWN_BLOB_HEADER_SIZE + offset;
}

const char *
kproc_spawn_blob_string(const struct kproc_spawn_blob *blob, uint32_t offset)
{
  const char *string;
  size_t remaining;

  if (offset >= blob->payload_length) {
    return NULL;
  }

  string = (const char *) blob->base + KPROC_SPAWN_BLOB_HEADER_SIZE + offset;
  remaining = blob->payload_length - offset;
  if (strnlen(string, remaining) == remaining) {
    return NULL;
  }

  return string;
}

bool
kproc_spawn_blob_strings(const struct kproc_spawn_blob *blob, uint32_t offset, const char **out, size_t count)
{
  uint32_t cursor = offset;

  if (count == 0) {
    return true;
  }

  if (offset >= blob->payload_length) {
    return false;
  }

  for (size_t i = 0; i != count; i++) {
    const char *string = kproc_spawn_blob_string(blob, cursor);
    size_t length;

    if (string == NULL) {
      return false;
    }

    out[i] = string;
    length = strlen(string) + 1;
    if (length > UINT32_MAX - cursor) {
      return false;
    }
    cursor += (uint32_t) length;
  }

  return true;
}
