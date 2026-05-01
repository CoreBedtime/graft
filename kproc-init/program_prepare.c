#include "program_prepare.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

extern const CFStringRef kSecCodeSignerIdentity;
extern const CFStringRef kSecCodeSignerEntitlements;
extern const CFStringRef kSecCodeSignerDigestAlgorithm;
typedef struct __SecCodeSigner *SecCodeSignerRef;
extern OSStatus SecCodeSignerCreate(CFDictionaryRef parameters, SecCSFlags flags, SecCodeSignerRef *signer);
extern OSStatus SecCodeSignerAddSignatureWithErrors(SecCodeSignerRef signer, SecStaticCodeRef code, SecCSFlags flags, CFErrorRef *errors);

static const uint32_t kEntitlementsBlobMagic = 0xFADE7171;

static bool
copy_string(const char *source, char *destination, size_t destination_size)
{
  int written;

  if (source == NULL || destination == NULL || destination_size == 0) {
    return false;
  }

  written = snprintf(destination, destination_size, "%s", source);
  return written >= 0 && (size_t) written < destination_size;
}

static const char *
env_value(const char *const envp[], const char *name)
{
  size_t name_length = strlen(name);

  if (envp == NULL) {
    return NULL;
  }

  for (size_t i = 0; envp[i] != NULL; i++) {
    if (strncmp(envp[i], name, name_length) == 0 && envp[i][name_length] == '=') {
      return envp[i] + name_length + 1;
    }
  }

  return NULL;
}

static int
resolve_executable_path(const char *program, bool use_path_search, const char *const envp[], char *resolved, size_t resolved_size)
{
  char *real_path;

  if (program == NULL || program[0] == '\0') {
    return EINVAL;
  }

  if (!use_path_search || strchr(program, '/') != NULL) {
    real_path = realpath(program, NULL);
    if (real_path == NULL) {
      return errno;
    }
    if (access(real_path, X_OK) != 0) {
      int error = errno;
      free(real_path);
      return error;
    }
    if (!copy_string(real_path, resolved, resolved_size)) {
      free(real_path);
      return ENAMETOOLONG;
    }
    free(real_path);
    return 0;
  }

  const char *path_env = env_value(envp, "PATH");
  if (path_env == NULL || path_env[0] == '\0') {
    path_env = "/usr/bin:/bin:/usr/sbin:/sbin";
  }

  char *path_copy = strdup(path_env);
  if (path_copy == NULL) {
    return ENOMEM;
  }

  int result = ENOENT;
  char *cursor = path_copy;
  char *entry;
  while ((entry = strsep(&cursor, ":")) != NULL) {
    char candidate[MAXPATHLEN];
    const char *directory = entry[0] == '\0' ? "." : entry;

    if (snprintf(candidate, sizeof(candidate), "%s/%s", directory, program) >= (int) sizeof(candidate)) {
      continue;
    }

    real_path = realpath(candidate, NULL);
    if (real_path == NULL) {
      continue;
    }
    if (access(real_path, X_OK) == 0 && copy_string(real_path, resolved, resolved_size)) {
      free(real_path);
      result = 0;
      break;
    }
    free(real_path);
  }

  free(path_copy);
  return result;
}

static bool
find_bundle_root_for_executable(const char *executable_path, char *bundle_root, size_t bundle_root_size)
{
  const char *marker = strstr(executable_path, ".app/Contents/MacOS/");
  size_t root_length;

  if (marker == NULL) {
    return false;
  }

  root_length = (size_t) (marker - executable_path) + strlen(".app");
  if (root_length + 1 > bundle_root_size) {
    return false;
  }

  memcpy(bundle_root, executable_path, root_length);
  bundle_root[root_length] = '\0';
  return true;
}

static bool
path_is_directory(const char *path)
{
  struct stat st;

  return path != NULL && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool
path_is_app_bundle(const char *path)
{
  size_t length;

  if (!path_is_directory(path)) {
    return false;
  }

  length = strlen(path);
  return length > 4 && strcmp(path + length - 4, ".app") == 0;
}

static bool
bundle_executable_path(const char *bundle_path, char *executable_path, size_t executable_path_size)
{
  CFURLRef bundle_url = NULL;
  CFBundleRef bundle = NULL;
  CFURLRef executable_url = NULL;
  bool ok = false;

  bundle_url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
                                                       (const UInt8 *) bundle_path,
                                                       (CFIndex) strlen(bundle_path),
                                                       true);
  if (bundle_url == NULL) {
    goto out;
  }

  bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  if (bundle == NULL) {
    goto out;
  }

  executable_url = CFBundleCopyExecutableURL(bundle);
  if (executable_url == NULL) {
    goto out;
  }

  ok = CFURLGetFileSystemRepresentation(executable_url,
                                         true,
                                         (UInt8 *) executable_path,
                                         (CFIndex) executable_path_size);

out:
  if (executable_url != NULL) {
    CFRelease(executable_url);
  }
  if (bundle != NULL) {
    CFRelease(bundle);
  }
  if (bundle_url != NULL) {
    CFRelease(bundle_url);
  }
  return ok;
}

static int copy_dir_recursive(const char *src_path, const char *dst_path);

static int
copy_regular_file(const char *src_path, const char *dst_path, mode_t mode)
{
  int src_fd = open(src_path, O_RDONLY);
  if (src_fd == -1) {
    return errno;
  }

  int dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, mode & 07777);
  if (dst_fd == -1) {
    int error = errno;
    close(src_fd);
    return error;
  }

  int result = 0;
  char buffer[65536];
  for (;;) {
    ssize_t nread = read(src_fd, buffer, sizeof(buffer));
    if (nread == 0) {
      break;
    }
    if (nread == -1) {
      result = errno;
      break;
    }

    ssize_t written = 0;
    while (written != nread) {
      ssize_t nwrite = write(dst_fd, buffer + written, (size_t) (nread - written));
      if (nwrite == -1) {
        result = errno;
        break;
      }
      written += nwrite;
    }
    if (result != 0) {
      break;
    }
  }

  if (result == 0 && fsync(dst_fd) == -1) {
    result = errno;
  }

  close(dst_fd);
  close(src_fd);
  return result;
}

static int
copy_symlink(const char *src_path, const char *dst_path)
{
  char target[MAXPATHLEN];
  ssize_t length = readlink(src_path, target, sizeof(target) - 1);

  if (length == -1) {
    return errno;
  }

  target[length] = '\0';
  if (symlink(target, dst_path) == -1) {
    return errno;
  }

  return 0;
}

static int
copy_dir_recursive(const char *src_path, const char *dst_path)
{
  struct stat st;
  DIR *dir;
  struct dirent *entry;
  int result = 0;

  if (lstat(src_path, &st) == -1) {
    return errno;
  }
  if (mkdir(dst_path, st.st_mode & 07777) == -1) {
    return errno;
  }

  dir = opendir(src_path);
  if (dir == NULL) {
    return errno;
  }

  while ((entry = readdir(dir)) != NULL) {
    char src_child[MAXPATHLEN];
    char dst_child[MAXPATHLEN];
    struct stat child_st;

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    if (snprintf(src_child, sizeof(src_child), "%s/%s", src_path, entry->d_name) >= (int) sizeof(src_child) ||
        snprintf(dst_child, sizeof(dst_child), "%s/%s", dst_path, entry->d_name) >= (int) sizeof(dst_child)) {
      result = ENAMETOOLONG;
      break;
    }

    if (lstat(src_child, &child_st) == -1) {
      result = errno;
      break;
    }

    if (S_ISDIR(child_st.st_mode)) {
      result = copy_dir_recursive(src_child, dst_child);
    } else if (S_ISREG(child_st.st_mode)) {
      result = copy_regular_file(src_child, dst_child, child_st.st_mode);
    } else if (S_ISLNK(child_st.st_mode)) {
      result = copy_symlink(src_child, dst_child);
    }

    if (result != 0) {
      break;
    }
  }

  closedir(dir);
  (void) chmod(dst_path, st.st_mode & 07777);
  return result;
}

static int
copy_bundle_to_temp(const char *bundle_path, const char *executable_path, struct kproc_prepared_program *prepared)
{
  char temp_root_template[] = "/tmp/kproc-init-bundle-XXXXXX";
  char *temp_root = mkdtemp(temp_root_template);
  const char *basename_start;
  char destination_bundle[MAXPATHLEN];
  size_t bundle_length;
  int result;

  if (temp_root == NULL) {
    return errno;
  }

  basename_start = strrchr(bundle_path, '/');
  basename_start = basename_start != NULL ? basename_start + 1 : bundle_path;
  if (snprintf(destination_bundle, sizeof(destination_bundle), "%s/%s", temp_root, basename_start) >= (int) sizeof(destination_bundle)) {
    return ENAMETOOLONG;
  }

  result = copy_dir_recursive(bundle_path, destination_bundle);
  if (result != 0) {
    return result;
  }

  bundle_length = strlen(bundle_path);
  if (strncmp(executable_path, bundle_path, bundle_length) != 0) {
    return EINVAL;
  }
  if (snprintf(prepared->path, sizeof(prepared->path), "%s%s", destination_bundle, executable_path + bundle_length) >= (int) sizeof(prepared->path)) {
    return ENAMETOOLONG;
  }
  if (!copy_string(destination_bundle, prepared->bundle_path, sizeof(prepared->bundle_path))) {
    return ENAMETOOLONG;
  }
  prepared->is_bundle_copy = true;
  return 0;
}

static int
copy_executable_to_temp(const char *executable_path, struct kproc_prepared_program *prepared)
{
  struct stat st;
  int src_fd;
  int dst_fd;
  char template_path[] = "/tmp/kproc-init-exec-XXXXXX";
  uint8_t *src_data;
  uint8_t *dst_data;
  size_t size;
  int result = 0;

  src_fd = open(executable_path, O_RDONLY);
  if (src_fd == -1) {
    return errno;
  }

  if (fstat(src_fd, &st) == -1) {
    result = errno;
    close(src_fd);
    return result;
  }

  size = (size_t) st.st_size;
  src_data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, src_fd, 0);
  if (src_data == MAP_FAILED) {
    result = errno;
    close(src_fd);
    return result;
  }

  dst_fd = mkstemp(template_path);
  if (dst_fd == -1) {
    result = errno;
    munmap(src_data, size);
    close(src_fd);
    return result;
  }

  if (fchmod(dst_fd, st.st_mode & 07777) == -1 || ftruncate(dst_fd, st.st_size) == -1) {
    result = errno;
    goto out;
  }

  dst_data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, dst_fd, 0);
  if (dst_data == MAP_FAILED) {
    result = errno;
    goto out;
  }

  memcpy(dst_data, src_data, size);
  if (msync(dst_data, size, MS_SYNC) == -1) {
    result = errno;
  }
  munmap(dst_data, size);

out:
  munmap(src_data, size);
  if (result == 0 && fsync(dst_fd) == -1) {
    result = errno;
  }
  close(dst_fd);
  close(src_fd);

  if (result != 0) {
    unlink(template_path);
    return result;
  }

  return copy_string(template_path, prepared->path, sizeof(prepared->path)) ? 0 : ENAMETOOLONG;
}

static void
depacify_thin(uint8_t *data, size_t size)
{
  struct mach_header_64 *header;
  struct load_command *command;

  if (size < sizeof(struct mach_header_64)) {
    return;
  }
  if (*(uint32_t *) data != MH_MAGIC_64) {
    return;
  }

  header = (struct mach_header_64 *) data;
  if (header->cputype != CPU_TYPE_ARM64 || (header->cpusubtype & 0xff) != 2) {
    return;
  }

  header->cpusubtype = 0;
  command = (struct load_command *) (data + sizeof(*header));
  for (uint32_t i = 0; i != header->ncmds; i++) {
    if ((uint8_t *) command + sizeof(*command) > data + size || command->cmdsize < sizeof(*command)) {
      return;
    }

    if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
      struct segment_command_64 *segment = (struct segment_command_64 *) command;
      if ((segment->initprot & VM_PROT_EXECUTE) != 0 && segment->fileoff < size) {
        size_t segment_size = segment->filesize;
        if (segment_size > size - segment->fileoff) {
          segment_size = size - segment->fileoff;
        }
        for (size_t offset = 0; offset + sizeof(uint32_t) <= segment_size; offset += sizeof(uint32_t)) {
          uint32_t *instruction = (uint32_t *) (data + segment->fileoff + offset);
          if ((*instruction & 0xfffff000) == 0xd5032000) {
            *instruction = 0xd503201f;
          }
        }
      }
    }

    command = (struct load_command *) ((uint8_t *) command + command->cmdsize);
  }
}

static void
depacify_macho(uint8_t *data, size_t size)
{
  uint32_t magic;

  if (size < sizeof(uint32_t)) {
    return;
  }

  magic = *(uint32_t *) data;
  if (magic == MH_MAGIC_64) {
    depacify_thin(data, size);
  } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
    struct fat_header *header = (struct fat_header *) data;
    uint32_t count = magic == FAT_CIGAM ? __builtin_bswap32(header->nfat_arch) : header->nfat_arch;
    struct fat_arch *arches;

    if (size < sizeof(*header) || count > (size - sizeof(*header)) / sizeof(struct fat_arch)) {
      return;
    }

    arches = (struct fat_arch *) (data + sizeof(*header));
    for (uint32_t i = 0; i != count; i++) {
      uint32_t offset = magic == FAT_CIGAM ? __builtin_bswap32(arches[i].offset) : arches[i].offset;
      uint32_t cputype = magic == FAT_CIGAM ? __builtin_bswap32(arches[i].cputype) : arches[i].cputype;
      uint32_t cpusubtype = magic == FAT_CIGAM ? __builtin_bswap32(arches[i].cpusubtype) : arches[i].cpusubtype;
      if (offset < size && cputype == CPU_TYPE_ARM64 && (cpusubtype & 0xff) == 2) {
        depacify_macho(data + offset, size - offset);
        arches[i].cpusubtype = magic == FAT_CIGAM ? __builtin_bswap32(0) : 0;
      }
    }
  }
}

static bool
strip_code_signature_thin(uint8_t *data, size_t size)
{
  struct mach_header_64 *header;
  uint8_t *src;
  uint8_t *dst;
  uint32_t new_ncmds = 0;
  uint32_t new_sizeofcmds = 0;
  uint32_t freed = 0;

  if (size < sizeof(struct mach_header_64) || *(uint32_t *) data != MH_MAGIC_64) {
    return true;
  }

  header = (struct mach_header_64 *) data;
  src = data + sizeof(*header);
  dst = src;
  for (uint32_t i = 0; i != header->ncmds; i++) {
    struct load_command *command;
    uint32_t command_size;

    if (src + sizeof(*command) > data + size) {
      return false;
    }

    command = (struct load_command *) src;
    command_size = command->cmdsize;
    if (command_size < sizeof(*command) || src + command_size > data + size) {
      return false;
    }

    if (command->cmd == LC_CODE_SIGNATURE) {
      freed += command_size;
    } else {
      if (dst != src) {
        memmove(dst, src, command_size);
      }
      dst += command_size;
      new_ncmds++;
      new_sizeofcmds += command_size;
    }
    src += command_size;
  }

  if (freed != 0) {
    memset(data + sizeof(*header) + new_sizeofcmds, 0, freed);
    header->ncmds = new_ncmds;
    header->sizeofcmds = new_sizeofcmds;
  }

  return true;
}

static bool
strip_code_signature_macho(uint8_t *data, size_t size)
{
  uint32_t magic;

  if (size < sizeof(uint32_t)) {
    return false;
  }

  magic = *(uint32_t *) data;
  if (magic == MH_MAGIC_64) {
    return strip_code_signature_thin(data, size);
  }
  if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
    struct fat_header *header = (struct fat_header *) data;
    uint32_t count = magic == FAT_CIGAM ? __builtin_bswap32(header->nfat_arch) : header->nfat_arch;
    struct fat_arch *arches;

    if (size < sizeof(*header) || count > (size - sizeof(*header)) / sizeof(struct fat_arch)) {
      return false;
    }

    arches = (struct fat_arch *) (data + sizeof(*header));
    for (uint32_t i = 0; i != count; i++) {
      uint32_t offset = magic == FAT_CIGAM ? __builtin_bswap32(arches[i].offset) : arches[i].offset;
      if (offset >= size || !strip_code_signature_macho(data + offset, size - offset)) {
        return false;
      }
    }
    return true;
  }

  return false;
}

static int
rewrite_macho_in_place(const char *path, bool strip_signature)
{
  int fd = open(path, O_RDWR);
  struct stat st;
  uint8_t *data;
  int result = 0;

  if (fd == -1) {
    return errno;
  }
  if (fstat(fd, &st) == -1) {
    result = errno;
    close(fd);
    return result;
  }

  data = mmap(NULL, (size_t) st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (data == MAP_FAILED) {
    result = errno;
    close(fd);
    return result;
  }

  depacify_macho(data, (size_t) st.st_size);
  if (strip_signature && !strip_code_signature_macho(data, (size_t) st.st_size)) {
    result = EINVAL;
  }

  if (result == 0 && msync(data, (size_t) st.st_size, MS_SYNC) == -1) {
    result = errno;
  }
  munmap(data, (size_t) st.st_size);
  if (result == 0 && fsync(fd) == -1) {
    result = errno;
  }
  close(fd);
  return result;
}

static CFDataRef
wrap_entitlements_xml(CFDataRef xml_data)
{
  CFIndex raw_length = CFDataGetLength(xml_data);
  uint32_t total_length;
  uint8_t *blob;
  CFDataRef wrapped;
  uint32_t magic;
  uint32_t size_be;

  if (raw_length > (CFIndex) (UINT32_MAX - 8)) {
    return NULL;
  }

  total_length = (uint32_t) raw_length + 8;
  blob = malloc(total_length);
  if (blob == NULL) {
    return NULL;
  }

  magic = CFSwapInt32HostToBig(kEntitlementsBlobMagic);
  size_be = CFSwapInt32HostToBig(total_length);
  memcpy(blob, &magic, sizeof(magic));
  memcpy(blob + 4, &size_be, sizeof(size_be));
  memcpy(blob + 8, CFDataGetBytePtr(xml_data), (size_t) raw_length);

  wrapped = CFDataCreate(kCFAllocatorDefault, blob, total_length);
  free(blob);
  return wrapped;
}

static CFDataRef
load_entitlements_from_code(const char *code_path)
{
  CFURLRef url = NULL;
  SecStaticCodeRef static_code = NULL;
  CFDictionaryRef signing_info = NULL;
  CFDataRef entitlements = NULL;
  OSStatus status;

  url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
                                                (const UInt8 *) code_path,
                                                (CFIndex) strlen(code_path),
                                                false);
  if (url == NULL) {
    return NULL;
  }

  status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &static_code);
  CFRelease(url);
  if (status != errSecSuccess) {
    return NULL;
  }

  status = SecCodeCopySigningInformation(static_code, kSecCSSigningInformation, &signing_info);
  CFRelease(static_code);
  if (status != errSecSuccess || signing_info == NULL) {
    return NULL;
  }

  entitlements = (CFDataRef) CFDictionaryGetValue(signing_info, kSecCodeInfoEntitlements);
  if (entitlements != NULL && CFGetTypeID(entitlements) == CFDataGetTypeID() && CFDataGetLength(entitlements) != 0) {
    CFRetain(entitlements);
    CFRelease(signing_info);
    return entitlements;
  }

  CFDictionaryRef entitlement_dict = (CFDictionaryRef) CFDictionaryGetValue(signing_info, kSecCodeInfoEntitlementsDict);
  if (entitlement_dict != NULL && CFGetTypeID(entitlement_dict) == CFDictionaryGetTypeID()) {
    CFErrorRef error = NULL;
    CFDataRef xml = CFPropertyListCreateData(kCFAllocatorDefault,
                                             entitlement_dict,
                                             kCFPropertyListXMLFormat_v1_0,
                                             0,
                                             &error);
    if (xml != NULL) {
      entitlements = wrap_entitlements_xml(xml);
      CFRelease(xml);
    }
    if (error != NULL) {
      CFRelease(error);
    }
  }

  CFRelease(signing_info);
  return entitlements;
}

static int
sign_file(const char *path, CFDataRef entitlements)
{
  CFMutableDictionaryRef parameters;
  CFNumberRef digest_number;
  CFArrayRef digest_array;
  SecCodeSignerRef signer = NULL;
  CFURLRef url = NULL;
  SecStaticCodeRef static_code = NULL;
  CFErrorRef error = NULL;
  OSStatus status;
  int digest_value = kSecCodeSignatureHashSHA256;

  parameters = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                         0,
                                         &kCFTypeDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);
  if (parameters == NULL) {
    return ENOMEM;
  }

  CFDictionaryAddValue(parameters, kSecCodeSignerIdentity, kCFNull);
  if (entitlements != NULL) {
    CFDictionaryAddValue(parameters, kSecCodeSignerEntitlements, entitlements);
  }

  digest_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &digest_value);
  if (digest_number == NULL) {
    CFRelease(parameters);
    return ENOMEM;
  }
  const void *digests[] = { digest_number };
  digest_array = CFArrayCreate(kCFAllocatorDefault, digests, 1, &kCFTypeArrayCallBacks);
  CFRelease(digest_number);
  if (digest_array == NULL) {
    CFRelease(parameters);
    return ENOMEM;
  }
  CFDictionaryAddValue(parameters, kSecCodeSignerDigestAlgorithm, digest_array);
  CFRelease(digest_array);

  status = SecCodeSignerCreate(parameters, kSecCSDefaultFlags, &signer);
  CFRelease(parameters);
  if (status != errSecSuccess) {
    return EINVAL;
  }

  url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
                                                (const UInt8 *) path,
                                                (CFIndex) strlen(path),
                                                false);
  if (url == NULL) {
    CFRelease(signer);
    return ENOMEM;
  }

  status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &static_code);
  CFRelease(url);
  if (status != errSecSuccess) {
    CFRelease(signer);
    return EINVAL;
  }

  status = SecCodeSignerAddSignatureWithErrors(signer, static_code, kSecCSDefaultFlags, &error);
  CFRelease(static_code);
  CFRelease(signer);
  if (error != NULL) {
    CFRelease(error);
  }

  return status == errSecSuccess ? 0 : EINVAL;
}

static int
depacify_and_resign(const char *prepared_path, const char *original_path)
{
  CFDataRef entitlements;
  int result;

  result = rewrite_macho_in_place(prepared_path, true);
  if (result != 0) {
    return result;
  }

  entitlements = load_entitlements_from_code(original_path);
  result = sign_file(prepared_path, entitlements);
  if (entitlements != NULL) {
    CFRelease(entitlements);
  }

  return result;
}

int
kproc_prepare_program(const char *program,
                      bool use_path_search,
                      const char *const envp[],
                      struct kproc_prepared_program *prepared)
{
  char executable_path[MAXPATHLEN];
  char bundle_root[MAXPATHLEN];
  int result;

  memset(prepared, 0, sizeof(*prepared));

  if (path_is_app_bundle(program)) {
    if (!bundle_executable_path(program, executable_path, sizeof(executable_path))) {
      return EINVAL;
    }
    result = copy_bundle_to_temp(program, executable_path, prepared);
    if (result != 0) {
      return result;
    }
    return depacify_and_resign(prepared->path, executable_path);
  }

  result = resolve_executable_path(program, use_path_search, envp, executable_path, sizeof(executable_path));
  if (result != 0) {
    return result;
  }

  if (find_bundle_root_for_executable(executable_path, bundle_root, sizeof(bundle_root))) {
    result = copy_bundle_to_temp(bundle_root, executable_path, prepared);
  } else {
    result = copy_executable_to_temp(executable_path, prepared);
  }
  if (result != 0) {
    return result;
  }

  return depacify_and_resign(prepared->path, executable_path);
}
