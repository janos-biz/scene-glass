#include <node_api.h>

#include <cerrno>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include <algorithm>
#include <array>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <new>
#include <uv.h>
#include <cstdio>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/file.h>

#if defined(__APPLE__)
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/xattr.h>
#elif defined(__linux__)
#include <sys/xattr.h>
#include <sys/syscall.h>
#else
#error "secure_read is only built for Darwin and Linux"
#endif

namespace {

constexpr uint32_t kMaximumReadBytes = 16U * 1024U * 1024U;
constexpr uint32_t kMaximumPathComponents = 256U;
constexpr size_t kMaximumPathBytes = 4U * 1024U;
constexpr size_t kMaximumPathComponentBytes = 255U;
constexpr size_t kMaximumInputStringBytes = 16U * 1024U;
constexpr size_t kMaximumIdentityDecimalBytes = 20U;
constexpr uint32_t kMaximumDeniedIdentities = 1024U;

constexpr const char* kPathDeniedCode = "SCG_NATIVE_PATH_DENIED";
constexpr const char* kIdentityMismatchCode = "SCG_NATIVE_IDENTITY_MISMATCH";
constexpr const char* kReadLimitCode = "SCG_NATIVE_READ_LIMIT";
constexpr const char* kNativeFailureCode = "SCG_NATIVE_FAILURE";
bool TryAcquireAuthoritySlot(std::atomic<uint32_t>* active, uint32_t maximum) {
  uint32_t current = active->load(std::memory_order_relaxed);
  while (current < maximum) {
    if (active->compare_exchange_weak(current, current + 1U, std::memory_order_acq_rel,
                                      std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}

void ReleaseAuthoritySlot(std::atomic<uint32_t>* active) {
  (void)active->fetch_sub(1U, std::memory_order_acq_rel);
}

class FileDescriptor final {
 public:
  explicit FileDescriptor(int fd = -1) : fd_(fd) {}

  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;

  FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.Release()) {}

  FileDescriptor& operator=(FileDescriptor&& other) noexcept {
    if (this != &other) {
      Reset(other.Release());
    }
    return *this;
  }

  ~FileDescriptor() { Reset(); }

  int Get() const { return fd_; }

  void Reset(int fd = -1) {
    const int previous_fd = fd_;
    fd_ = fd;
    if (previous_fd >= 0 && previous_fd != fd) {
      (void)close(previous_fd);
    }
  }

  int Release() {
    const int fd = fd_;
    fd_ = -1;
    return fd;
  }

 private:
  int fd_;
};

void ZeroizeMemory(void* data, size_t size) {
  if (data == nullptr) {
    return;
  }

  volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
  for (size_t index = 0; index < size; ++index) {
    cursor[index] = 0;
  }
}
void ZeroizeString(std::string* value) {
  if (value == nullptr || value->empty()) {
    return;
  }
  ZeroizeMemory(value->data(), value->size());
  value->clear();
}


class SensitiveBytes final {
 public:
  explicit SensitiveBytes(size_t size) : bytes_(size) {}

  SensitiveBytes(const SensitiveBytes&) = delete;
  SensitiveBytes& operator=(const SensitiveBytes&) = delete;
  SensitiveBytes(SensitiveBytes&& other) noexcept : bytes_(std::move(other.bytes_)) {}

  SensitiveBytes& operator=(SensitiveBytes&& other) noexcept {
    if (this != &other) {
      ZeroizeMemory(bytes_.data(), bytes_.size());
      bytes_ = std::move(other.bytes_);
    }
    return *this;
  }

  ~SensitiveBytes() { ZeroizeMemory(bytes_.data(), bytes_.size()); }

  unsigned char* Data() { return bytes_.data(); }
  const unsigned char* Data() const { return bytes_.data(); }
  size_t Size() const { return bytes_.size(); }

 private:
  std::vector<unsigned char> bytes_;
};
std::string Sha256Digest(const SensitiveBytes& bytes);

struct Identity {
  uint64_t device;
  uint64_t inode;
};

struct Options {
  std::string root_path;
  bool has_expected_root;
  Identity expected_root;
  std::string relative_path;
  bool has_expected_authority;
  Identity expected_authority;
  std::vector<Identity> denied_identities;
  uint32_t max_bytes;
  bool read_content;
};

struct TrustState {
  bool user_phase = false;
  uint64_t user_device = 0;
  uid_t euid = 0;
};

void Throw(napi_env env, const char* code, const char* message) {
  napi_throw_error(env, code, message);
}

bool GetRequiredProperty(napi_env env, napi_value object, const char* name, napi_value* value) {
  bool has_property = false;
  if (napi_has_named_property(env, object, name, &has_property) != napi_ok || !has_property) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  if (napi_get_named_property(env, object, name, value) != napi_ok) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  return true;
}

bool GetObject(napi_env env, napi_value value, napi_value* object) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_object || value == nullptr) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  *object = value;
  return true;
}

bool GetString(napi_env env, napi_value value, std::string* output,
               size_t maximum_bytes = kMaximumInputStringBytes) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_string) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length > maximum_bytes) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  std::vector<char> parsed_bytes(length + 1U);
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, parsed_bytes.data(), parsed_bytes.size(), &copied) !=
      napi_ok) {
    ZeroizeMemory(parsed_bytes.data(), parsed_bytes.size());
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  std::string parsed(parsed_bytes.data(), copied);
  ZeroizeMemory(parsed_bytes.data(), parsed_bytes.size());
  if (parsed.find('\0') != std::string::npos) {
    ZeroizeString(&parsed);
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  *output = std::move(parsed);
  return true;
}

bool ParseDecimalIdentityPart(napi_env env, napi_value value, uint64_t* output) {
  std::string decimal;
  if (!GetString(env, value, &decimal, kMaximumIdentityDecimalBytes)) {
    return false;
  }
  if (decimal.empty() || (decimal.size() > 1 && decimal[0] == '0')) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  uint64_t parsed = 0;
  for (const char character : decimal) {
    if (character < '0' || character > '9') {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
    const uint64_t digit = static_cast<uint64_t>(character - '0');
    if (parsed > (UINT64_MAX - digit) / 10U) {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
    parsed = parsed * 10U + digit;
  }
  *output = parsed;
  return true;
}

bool ParseIdentity(napi_env env, napi_value value, Identity* output) {
  napi_value object;
  napi_value device;
  napi_value inode;
  if (!GetObject(env, value, &object) || !GetRequiredProperty(env, object, "device", &device) ||
      !GetRequiredProperty(env, object, "inode", &inode) ||
      !ParseDecimalIdentityPart(env, device, &output->device) ||
      !ParseDecimalIdentityPart(env, inode, &output->inode)) {
    return false;
  }
  return true;
}


bool ParseComponents(napi_env env, const std::string& path, bool absolute,
                     std::vector<std::string>* components) {
  if (path.empty() || (absolute && path[0] != '/') || (!absolute && path[0] == '/')) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  if (path.size() > 1U && path.back() == '/') {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  if (path.size() > kMaximumPathBytes) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  size_t begin = absolute ? 1U : 0U;
  if (absolute && path.size() == 1U) {
    return true;
  }
  while (begin < path.size()) {
    const size_t end = path.find('/', begin);
    const size_t length = (end == std::string::npos ? path.size() : end) - begin;
    if (length == 0U || length > kMaximumPathComponentBytes ||
        components->size() >= kMaximumPathComponents) {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
    const std::string component = path.substr(begin, length);
    if (component == "." || component == ".." || component.find('\0') != std::string::npos) {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
    components->push_back(component);
    if (end == std::string::npos) {
      break;
    }
    begin = end + 1U;
  }
  return true;
}

bool ParseOptions(napi_env env, napi_callback_info info, Options* output) {
  size_t argument_count = 1;
  napi_value argument;
  if (napi_get_cb_info(env, info, &argument_count, &argument, nullptr, nullptr) != napi_ok ||
      argument_count != 1U) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  napi_value options;
  napi_value root;
  napi_value expected_root;
  napi_value relative_path;
  napi_value expected_authority;
  napi_value denied_identities;
  napi_value max_bytes;
  napi_value read_content;
  if (!GetObject(env, argument, &options) || !GetRequiredProperty(env, options, "root", &root) ||
      !GetRequiredProperty(env, options, "expectedRoot", &expected_root) ||
      !GetRequiredProperty(env, options, "relativePath", &relative_path) ||
      !GetRequiredProperty(env, options, "expectedAuthority", &expected_authority) ||
      !GetRequiredProperty(env, options, "deniedIdentities", &denied_identities) ||
      !GetRequiredProperty(env, options, "maxBytes", &max_bytes) ||
      !GetRequiredProperty(env, options, "readContent", &read_content) ||
      !GetString(env, root, &output->root_path, kMaximumPathBytes) ||
      !GetString(env, relative_path, &output->relative_path, kMaximumPathBytes)) {
    return false;
  }

  napi_valuetype expected_root_type;
  napi_valuetype expected_authority_type;
  if (napi_typeof(env, expected_root, &expected_root_type) != napi_ok ||
      napi_typeof(env, expected_authority, &expected_authority_type) != napi_ok) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  output->has_expected_root = expected_root_type != napi_null;
  output->has_expected_authority = expected_authority_type != napi_null;
  if (output->has_expected_root && !ParseIdentity(env, expected_root, &output->expected_root)) {
    return false;
  }
  if (output->has_expected_authority &&
      !ParseIdentity(env, expected_authority, &output->expected_authority)) {
    return false;
  }

  napi_valuetype max_bytes_type;
  double max_bytes_value = 0;
  if (napi_typeof(env, max_bytes, &max_bytes_type) != napi_ok || max_bytes_type != napi_number ||
      napi_get_value_double(env, max_bytes, &max_bytes_value) != napi_ok ||
      !std::isfinite(max_bytes_value) || std::trunc(max_bytes_value) != max_bytes_value ||
      max_bytes_value < 0 || max_bytes_value > static_cast<double>(kMaximumReadBytes)) {
    Throw(env, kReadLimitCode, "secure native read limit exceeded");
    return false;
  }
  output->max_bytes = static_cast<uint32_t>(max_bytes_value);

  napi_valuetype read_content_type;
  if (napi_typeof(env, read_content, &read_content_type) != napi_ok || read_content_type != napi_boolean ||
      napi_get_value_bool(env, read_content, &output->read_content) != napi_ok) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  bool is_array = false;
  if (napi_is_array(env, denied_identities, &is_array) != napi_ok || !is_array) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  uint32_t denied_count = 0;
  if (napi_get_array_length(env, denied_identities, &denied_count) != napi_ok ||
      denied_count > kMaximumDeniedIdentities) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  output->denied_identities.reserve(denied_count);
  for (uint32_t index = 0; index < denied_count; ++index) {
    napi_value identity;
    Identity parsed{};
    if (napi_get_element(env, denied_identities, index, &identity) != napi_ok ||
        !ParseIdentity(env, identity, &parsed)) {
      return false;
    }
    for (const Identity& existing : output->denied_identities) {
      if (existing.device == parsed.device && existing.inode == parsed.inode) {
        Throw(env, kPathDeniedCode, "secure native read denied");
        return false;
      }
    }
    output->denied_identities.push_back(parsed);
  }
  return true;
}

bool HasSafeAcl(int fd) {
#if defined(__APPLE__)
  errno = 0;
  acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
  if (acl == nullptr) {
    return errno == ENOENT;
  }

  bool safe = true;
  acl_entry_t entry = nullptr;
  int entry_result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
  while (entry_result == 0 && entry != nullptr) {
    acl_tag_t tag;
    if (acl_get_tag_type(entry, &tag) != 0 || tag != ACL_EXTENDED_DENY) {
      safe = false;
      break;
    }
    entry = nullptr;
    errno = 0;
    entry_result = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
  }
  if (safe && entry_result < 0 && errno != EINVAL) {
    safe = false;
  }
  (void)acl_free(acl);
  return safe;
#else
  errno = 0;
  const ssize_t access_acl_size = fgetxattr(fd, "system.posix_acl_access", nullptr, 0);
  if (access_acl_size >= 0 || errno != ENODATA) {
    return false;
  }
  errno = 0;
  const ssize_t default_acl_size = fgetxattr(fd, "system.posix_acl_default", nullptr, 0);
  return default_acl_size < 0 && errno == ENODATA;
#endif
}
bool ClearInheritedAcl(int fd) {
#if defined(__APPLE__)
  acl_t acl = acl_init(0);
  if (acl == nullptr) {
    return false;
  }
  const bool cleared = acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0;
  (void)acl_free(acl);
  return cleared;
#else
  if (fremovexattr(fd, "system.posix_acl_access") != 0 && errno != ENODATA) {
    return false;
  }
  if (fremovexattr(fd, "system.posix_acl_default") != 0 && errno != ENODATA) {
    return false;
  }
  return true;
#endif
}

bool IsLifecycleOwner(const struct stat& stat) {
  return stat.st_uid == geteuid();
}
bool IsLifecycleDirectoryOwner(const struct stat& stat) {
  return stat.st_uid == 0 || IsLifecycleOwner(stat);
}

bool SameIdentity(const struct stat& stat, const Identity& identity) {
  return static_cast<uint64_t>(stat.st_dev) == identity.device &&
         static_cast<uint64_t>(stat.st_ino) == identity.inode;
}
bool SameIdentity(const Identity& left, const Identity& right);

bool SameFileState(const struct stat& before, const struct stat& after) {
  if (before.st_dev != after.st_dev || before.st_ino != after.st_ino || before.st_mode != after.st_mode ||
      before.st_uid != after.st_uid || before.st_nlink != after.st_nlink || before.st_size != after.st_size) {
    return false;
  }
#if defined(__APPLE__)
  return before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
         before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
         before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
         before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
  return before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
         before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
         before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
         before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
}
std::string LifecycleStatSnapshot(const struct stat& stat) {
#if defined(__APPLE__)
  const auto modified_seconds = stat.st_mtimespec.tv_sec;
  const auto modified_nanoseconds = stat.st_mtimespec.tv_nsec;
  const auto changed_seconds = stat.st_ctimespec.tv_sec;
  const auto changed_nanoseconds = stat.st_ctimespec.tv_nsec;
#else
  const auto modified_seconds = stat.st_mtim.tv_sec;
  const auto modified_nanoseconds = stat.st_mtim.tv_nsec;
  const auto changed_seconds = stat.st_ctim.tv_sec;
  const auto changed_nanoseconds = stat.st_ctim.tv_nsec;
#endif
  return std::to_string(static_cast<uint64_t>(stat.st_dev)) + ":" +
         std::to_string(static_cast<uint64_t>(stat.st_ino)) + ":" +
         std::to_string(static_cast<uint64_t>(stat.st_mode)) + ":" +
         std::to_string(static_cast<uint64_t>(stat.st_uid)) + ":" +
         std::to_string(static_cast<uint64_t>(stat.st_nlink)) + ":" +
         std::to_string(static_cast<int64_t>(stat.st_size)) + ":" +
         std::to_string(static_cast<int64_t>(modified_seconds)) + ":" +
         std::to_string(static_cast<int64_t>(modified_nanoseconds)) + ":" +
         std::to_string(static_cast<int64_t>(changed_seconds)) + ":" +
         std::to_string(static_cast<int64_t>(changed_nanoseconds));
}

bool IsSecureMode(const struct stat& stat) {
  return (stat.st_mode & (S_IWGRP | S_IWOTH | S_ISVTX)) == 0;
}

bool IsCredentialMode(const struct stat& stat) {
  return static_cast<mode_t>(stat.st_mode & 07777) == 0600;
}

bool ReadStat(int fd, struct stat* output) {
  return fstat(fd, output) == 0;
}

bool ValidateDirectory(napi_env env, int fd, TrustState* state, struct stat* output) {
  struct stat stat{};
  if (!ReadStat(fd, &stat) || !S_ISDIR(stat.st_mode) || !IsSecureMode(stat) || !HasSafeAcl(fd)) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  const uint64_t device = static_cast<uint64_t>(stat.st_dev);
  if (state->user_phase) {
    if (stat.st_uid != state->euid || device != state->user_device) {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
  } else if (stat.st_uid == state->euid) {
    state->user_phase = true;
    state->user_device = device;
  } else if (stat.st_uid != 0) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  *output = stat;
  return true;
}

bool ValidateRootDirectory(napi_env env, int fd, struct stat* output) {
  struct stat stat{};
  if (!ReadStat(fd, &stat) || !S_ISDIR(stat.st_mode) || stat.st_uid != 0 || !IsSecureMode(stat) ||
      !HasSafeAcl(fd)) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }
  *output = stat;
  return true;
}

bool ValidateFinalFile(napi_env env, int fd, TrustState* state, struct stat* output) {
  struct stat stat{};
  if (!ReadStat(fd, &stat) || !S_ISREG(stat.st_mode) || stat.st_nlink != 1 || !IsSecureMode(stat) ||
      !HasSafeAcl(fd)) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  const uint64_t device = static_cast<uint64_t>(stat.st_dev);
  if (state->user_phase) {
    if (stat.st_uid != state->euid || device != state->user_device) {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
  } else if (stat.st_uid == state->euid) {
    state->user_phase = true;
    state->user_device = device;
  } else {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  *output = stat;
  return true;
}
bool ValidateCredentialFinalFile(napi_env env, int fd, TrustState* state, struct stat* output) {
  struct stat stat{};
  if (!ReadStat(fd, &stat) || !S_ISREG(stat.st_mode) || stat.st_nlink != 1 ||
      stat.st_uid != state->euid || !IsCredentialMode(stat) || !HasSafeAcl(fd)) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return false;
  }

  const uint64_t device = static_cast<uint64_t>(stat.st_dev);
  if (state->user_phase) {
    if (device != state->user_device) {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
  } else {
    state->user_phase = true;
    state->user_device = device;
  }

  *output = stat;
  return true;
}


int OpenDirectoryAt(int parent_fd, const std::string& component) {
  return openat(parent_fd, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int OpenFinalAt(int parent_fd, const std::string& component) {
  return openat(parent_fd, component.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
}

bool IsDenied(const Identity& identity, const std::vector<Identity>& denied_identities) {
  for (const Identity& denied : denied_identities) {
    if (identity.device == denied.device && identity.inode == denied.inode) {
      return true;
    }
  }
  return false;
}

bool ReadBoundedFile(napi_env env, int fd, const struct stat& before, uint32_t max_bytes,
                     SensitiveBytes* bytes) {
  if (before.st_size < 0 || static_cast<uint64_t>(before.st_size) > max_bytes) {
    Throw(env, kReadLimitCode, "secure native read limit exceeded");
    return false;
  }
  if (static_cast<uint64_t>(before.st_size) != bytes->Size()) {
    Throw(env, kReadLimitCode, "secure native read limit exceeded");
    return false;
  }

  size_t offset = 0;
  while (offset < bytes->Size()) {
    const ssize_t read_count = pread(fd, bytes->Data() + offset, bytes->Size() - offset,
                                     static_cast<off_t>(offset));
    if (read_count < 0 && errno == EINTR) {
      continue;
    }
    if (read_count <= 0) {
      Throw(env, kPathDeniedCode, "secure native read denied");
      return false;
    }
    offset += static_cast<size_t>(read_count);
  }
  return true;
}
bool CreateSecureReadResult(napi_env env, const SensitiveBytes& bytes, const struct stat& stat,
                            napi_value* output) {
  constexpr uint64_t kMaximumSafeJavaScriptInteger = 9007199254740991ULL;
  const uint64_t link_count = static_cast<uint64_t>(stat.st_nlink);
  const uint64_t mode = static_cast<uint64_t>(stat.st_mode);
  if (link_count > kMaximumSafeJavaScriptInteger || mode > UINT32_MAX) {
    Throw(env, kNativeFailureCode, "secure native read failed");
    return false;
  }

  napi_value result;
  napi_value content;
  napi_value identity;
  napi_value device;
  napi_value inode;
  napi_value native_link_count;
  napi_value native_mode;
  void* content_data = nullptr;
  const std::string device_string = std::to_string(static_cast<uint64_t>(stat.st_dev));
  const std::string inode_string = std::to_string(static_cast<uint64_t>(stat.st_ino));
  if (napi_create_object(env, &result) != napi_ok ||
      napi_create_buffer_copy(env, bytes.Size(), bytes.Size() == 0U ? nullptr : bytes.Data(),
                              &content_data, &content) != napi_ok ||
      napi_create_object(env, &identity) != napi_ok ||
      napi_create_string_utf8(env, device_string.c_str(), device_string.size(), &device) != napi_ok ||
      napi_create_string_utf8(env, inode_string.c_str(), inode_string.size(), &inode) != napi_ok ||
      napi_create_double(env, static_cast<double>(link_count), &native_link_count) != napi_ok ||
      napi_create_uint32(env, static_cast<uint32_t>(mode), &native_mode) != napi_ok ||
      napi_set_named_property(env, identity, "device", device) != napi_ok ||
      napi_set_named_property(env, identity, "inode", inode) != napi_ok ||
      napi_set_named_property(env, result, "bytes", content) != napi_ok ||
      napi_set_named_property(env, result, "identity", identity) != napi_ok ||
      napi_set_named_property(env, result, "linkCount", native_link_count) != napi_ok ||
      napi_set_named_property(env, result, "mode", native_mode) != napi_ok) {
    ZeroizeMemory(content_data, bytes.Size());
    Throw(env, kNativeFailureCode, "secure native read failed");
    return false;
  }

  *output = result;
  return true;
}

napi_value SecureReadBeneath(napi_env env, napi_callback_info info) {
  Options options{};
  if (!ParseOptions(env, info, &options)) {
    return nullptr;
  }

  std::vector<std::string> root_components;
  std::vector<std::string> relative_components;
  if (!ParseComponents(env, options.root_path, true, &root_components) ||
      !ParseComponents(env, options.relative_path, false, &relative_components) || relative_components.empty()) {
    return nullptr;
  }

  TrustState trust_state{};
  trust_state.euid = geteuid();

  FileDescriptor current(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  struct stat root_stat{};
  if (current.Get() < 0 || !ValidateRootDirectory(env, current.Get(), &root_stat)) {
    if (current.Get() < 0) {
      Throw(env, kPathDeniedCode, "secure native read denied");
    }
    return nullptr;
  }

  for (const std::string& component : root_components) {
    FileDescriptor next(OpenDirectoryAt(current.Get(), component));
    struct stat component_stat{};
    if (next.Get() < 0 || !ValidateDirectory(env, next.Get(), &trust_state, &component_stat)) {
      if (next.Get() < 0) {
        Throw(env, kPathDeniedCode, "secure native read denied");
      }
      return nullptr;
    }
    current = std::move(next);
    root_stat = component_stat;
  }

  if (options.has_expected_root && !SameIdentity(root_stat, options.expected_root)) {
    Throw(env, kIdentityMismatchCode, "secure native read identity mismatch");
    return nullptr;
  }

  for (size_t index = 0; index + 1U < relative_components.size(); ++index) {
    FileDescriptor next(OpenDirectoryAt(current.Get(), relative_components[index]));
    struct stat component_stat{};
    if (next.Get() < 0 || !ValidateDirectory(env, next.Get(), &trust_state, &component_stat)) {
      if (next.Get() < 0) {
        Throw(env, kPathDeniedCode, "secure native read denied");
      }
      return nullptr;
    }
    current = std::move(next);
  }

  FileDescriptor final_fd(OpenFinalAt(current.Get(), relative_components.back()));
  struct stat before{};
  if (final_fd.Get() < 0 ||
      !(options.has_expected_authority
            ? ValidateCredentialFinalFile(env, final_fd.Get(), &trust_state, &before)
            : ValidateFinalFile(env, final_fd.Get(), &trust_state, &before))) {
    if (final_fd.Get() < 0) {
      Throw(env, kPathDeniedCode, "secure native read denied");
    }
    return nullptr;
  }

  const Identity final_identity{static_cast<uint64_t>(before.st_dev),
                                static_cast<uint64_t>(before.st_ino)};
  if (options.has_expected_authority &&
      (final_identity.device != options.expected_authority.device ||
       final_identity.inode != options.expected_authority.inode)) {
    Throw(env, kIdentityMismatchCode, "secure native read identity mismatch");
    return nullptr;
  }
  if (IsDenied(final_identity, options.denied_identities)) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return nullptr;
  }

  if (before.st_size < 0 || static_cast<uint64_t>(before.st_size) > options.max_bytes) {
    Throw(env, kReadLimitCode, "secure native read limit exceeded");
    return nullptr;
  }
  SensitiveBytes bytes(options.read_content ? static_cast<size_t>(before.st_size) : 0U);
  if (options.read_content && !ReadBoundedFile(env, final_fd.Get(), before, options.max_bytes, &bytes)) {
    return nullptr;
  }

  struct stat after{};
  if (!(options.has_expected_authority
            ? ValidateCredentialFinalFile(env, final_fd.Get(), &trust_state, &after)
            : ValidateFinalFile(env, final_fd.Get(), &trust_state, &after))) {
    return nullptr;
  }
  if (!SameFileState(before, after)) {
    Throw(env, kPathDeniedCode, "secure native read denied");
    return nullptr;
  }

  napi_value result;
  if (!CreateSecureReadResult(env, bytes, after, &result)) {
    return nullptr;
  }
  return result;
}

constexpr uint32_t kMaximumViteCacheEntries = 2000U;
constexpr uint32_t kMaximumViteCacheFiles = 1000U;
constexpr uint32_t kMaximumViteCacheBytes = 64U * 1024U * 1024U;
constexpr uint32_t kMaximumViteCacheDepth = 8U;
constexpr uint32_t kMaximumViteCacheTokenHashes = 1024U;
constexpr uint32_t kMaximumViteCacheCredentialBytes = 8U * 1024U;
constexpr uint64_t kMaximumViteCacheMatcherWorkUnits = 64U * 1024U;
constexpr uint32_t kMaximumViteCacheWatchers = 8U;
constexpr uint32_t kMaximumViteCacheSessions = 8U;
std::atomic<uint32_t> active_vite_cache_sessions{0U};
std::atomic<uint32_t> active_vite_cache_watchers{0U};
constexpr uint32_t kMaximumViteCacheWatcherPolls = 600U;
constexpr uint64_t kMaximumSafeJavaScriptInteger = 9007199254740991ULL;
constexpr uint64_t kViteCacheWatcherIntervalMilliseconds = 100U;
using ViteCacheTokenHash = std::array<unsigned char, 64U>;

struct ViteCacheTokenHashes final {
  ViteCacheTokenHashes() = default;
  ViteCacheTokenHashes(const ViteCacheTokenHashes&) = delete;
  ViteCacheTokenHashes& operator=(const ViteCacheTokenHashes&) = delete;
  ~ViteCacheTokenHashes() { Clear(); }

  void Clear() {
    for (ViteCacheTokenHash& value : values) {
      ZeroizeMemory(value.data(), value.size());
    }
    values.clear();
  }

  std::vector<ViteCacheTokenHash> values;
};

const napi_type_tag kViteCacheSessionTypeTag = {0x39a968b4e52c4d71ULL, 0x9a0d51f8768f2b8eULL};
const napi_type_tag kViteCacheWatcherTypeTag = {0xbe5ee39a80634258ULL, 0xb7484b7686712f55ULL};

struct ViteCacheRecord {
  std::string canonical_path;
  Identity identity;
  uid_t uid;
  gid_t gid;
  mode_t mode;
};

struct ViteCacheProvenanceNative {
  std::string install_id;
  std::string canonical_parent_path;
  ViteCacheRecord root;
  ViteCacheRecord parent;
  Identity parent_identity;
};

struct ViteCacheLimitsNative {
  uint32_t max_entries;
  uint32_t max_files;
  uint32_t max_bytes;
  uint32_t max_depth;
};

struct ViteCacheWatcher;

struct ViteCacheSession {
  FileDescriptor parent_fd;
  FileDescriptor root_fd;
  ViteCacheProvenanceNative provenance;
  bool closed = false;
  bool slot_charged = false;
  std::vector<ViteCacheWatcher*> watchers;
};

struct ViteCacheTreeEntry {
  Identity identity;
  Identity parent_identity;
  bool has_parent_identity;
  uint64_t device;
  uid_t uid;
  gid_t gid;
  mode_t mode;
  uint64_t size_bytes;
  uint64_t link_count;
  uint32_t depth;
  int kind;
  int64_t modified_seconds;
  int64_t modified_nanoseconds;
  int64_t changed_seconds;
  int64_t changed_nanoseconds;
};

enum ViteCacheEntryKind {
  kViteCacheDirectory,
  kViteCacheRegularFile,
  kViteCacheSymlink,
  kViteCacheSocket,
  kViteCacheFifo,
  kViteCacheBlockDevice,
  kViteCacheCharacterDevice,
  kViteCacheUnknown,
};

struct ViteCacheTreeResult {
  std::vector<ViteCacheTreeEntry> entries;
  uint32_t file_count = 0;
  uint64_t aggregate_bytes = 0;
};

bool IsNapiStatusOk(napi_status status) {
  return status == napi_ok;
}

void ThrowCacheDenied(napi_env env) {
  Throw(env, kPathDeniedCode, "secure native cache operation denied");
}


void ThrowCacheFailure(napi_env env) {
  Throw(env, kNativeFailureCode, "secure native cache operation failed");
}

bool GetSingleObjectArgument(napi_env env, napi_callback_info info, napi_value* output) {
  size_t argument_count = 1;
  napi_value argument;
  if (!IsNapiStatusOk(napi_get_cb_info(env, info, &argument_count, &argument, nullptr, nullptr)) ||
      argument_count != 1U || !GetObject(env, argument, output)) {
    if (argument_count != 1U) {
      ThrowCacheDenied(env);
    }
    return false;
  }
  return true;
}

bool GetUint32(napi_env env, napi_value value, uint32_t maximum, uint32_t* output) {
  napi_valuetype type;
  double numeric = 0;
  if (!IsNapiStatusOk(napi_typeof(env, value, &type)) || type != napi_number ||
      !IsNapiStatusOk(napi_get_value_double(env, value, &numeric)) || !std::isfinite(numeric) ||
      std::trunc(numeric) != numeric || numeric < 0 ||
      numeric > static_cast<double>(maximum)) {
    ThrowCacheDenied(env);
    return false;
  }
  *output = static_cast<uint32_t>(numeric);
  return true;
}

bool GetRequiredUint32(napi_env env, napi_value object, const char* name, uint32_t maximum,
                       uint32_t* output) {
  napi_value value;
  return GetRequiredProperty(env, object, name, &value) && GetUint32(env, value, maximum, output);
}

bool IsViteCacheInstallId(const std::string& value) {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  for (const char character : value) {
    if (!((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || character == '_' || character == '-')) {
      return false;
    }
  }
  return true;
}

bool ParseCanonicalAbsolutePath(napi_env env, napi_value value, std::string* output) {
  if (!GetString(env, value, output, kMaximumPathBytes)) {
    return false;
  }
  std::vector<std::string> components;
  return ParseComponents(env, *output, true, &components);
}

constexpr uint32_t kMaximumLifecycleWriteBytes = 32U * 1024U * 1024U;
constexpr uint32_t kMaximumLifecycleLocks = 16U;
constexpr uint32_t kMaximumLifecycleReservations = 64U;
constexpr uint32_t kMaximumLifecycleQuarantines = 64U;
std::atomic<uint32_t> active_lifecycle_locks{0U};
std::atomic<uint32_t> active_lifecycle_reservations{0U};
std::atomic<uint32_t> active_lifecycle_quarantines{0U};
std::atomic<uint64_t> next_lifecycle_lock_session_generation{1U};

void ThrowLifecycleDenied(napi_env env) {
  Throw(env, kPathDeniedCode, "secure lifecycle filesystem operation denied");
}

void ThrowLifecycleIdentityMismatch(napi_env env) {
  Throw(env, kIdentityMismatchCode, "secure lifecycle filesystem identity mismatch");
}

void ThrowLifecycleFailure(napi_env env) {
  Throw(env, kNativeFailureCode, "secure lifecycle filesystem operation failed");
}

bool ParseLifecyclePath(napi_env env, napi_value value, std::string* output) {
  if (!ParseCanonicalAbsolutePath(env, value, output)) {
    return false;
  }
  std::vector<std::string> components;
  if (!ParseComponents(env, *output, true, &components) || components.empty()) {
    if (components.empty()) {
      ThrowLifecycleDenied(env);
    }
    return false;
  }
  return true;
}

bool ParseLifecycleMode(napi_env env, napi_value value, mode_t* output) {
  uint32_t mode = 0U;
  if (!GetUint32(env, value, 07777U, &mode)) {
    return false;
  }
  *output = static_cast<mode_t>(mode);
  return true;
}

bool ParseLifecycleSize(napi_env env, napi_value value, uint32_t* output) {
  return GetUint32(env, value, kMaximumLifecycleWriteBytes, output);
}

bool ParseLifecycleBytes(napi_env env, napi_value value, SensitiveBytes* output) {
  bool is_buffer = false;
  void* bytes = nullptr;
  size_t byte_count = 0U;
  if (!IsNapiStatusOk(napi_is_buffer(env, value, &is_buffer)) || !is_buffer ||
      !IsNapiStatusOk(napi_get_buffer_info(env, value, &bytes, &byte_count)) ||
      byte_count > kMaximumLifecycleWriteBytes) {
    ThrowLifecycleDenied(env);
    return false;
  }
  SensitiveBytes copied(byte_count);
  if (byte_count > 0U) {
    std::memcpy(copied.Data(), bytes, byte_count);
  }
  *output = std::move(copied);
  return true;
}

bool OpenLifecycleParent(napi_env env, const std::string& path, FileDescriptor* parent,
                         std::string* name) {
  std::vector<std::string> components;
  if (!ParseComponents(env, path, true, &components) || components.empty()) {
    if (components.empty()) {
      ThrowLifecycleDenied(env);
    }
    return false;
  }

  FileDescriptor current(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  struct stat current_stat{};
  if (current.Get() < 0 || fstat(current.Get(), &current_stat) != 0 ||
      !S_ISDIR(current_stat.st_mode) || current_stat.st_uid != 0 || !IsSecureMode(current_stat) ||
      !HasSafeAcl(current.Get())) {
    ThrowLifecycleDenied(env);
    return false;
  }

  for (size_t index = 0U; index + 1U < components.size(); ++index) {
    FileDescriptor next(OpenDirectoryAt(current.Get(), components[index]));
    struct stat next_stat{};
    if (next.Get() < 0 || fstat(next.Get(), &next_stat) != 0 || !S_ISDIR(next_stat.st_mode) ||
        !IsLifecycleDirectoryOwner(next_stat) || !IsSecureMode(next_stat) || !HasSafeAcl(next.Get())) {
      ThrowLifecycleDenied(env);
      return false;
    }
    current = std::move(next);
  }

  struct stat parent_stat{};
  if (fstat(current.Get(), &parent_stat) != 0 || !S_ISDIR(parent_stat.st_mode) ||
      !IsLifecycleDirectoryOwner(parent_stat) || !IsSecureMode(parent_stat) ||
      !HasSafeAcl(current.Get())) {
    ThrowLifecycleDenied(env);
    return false;
  }
  *name = components.back();
  *parent = std::move(current);
  return true;
}

Identity LifecycleIdentityFromStat(const struct stat& stat) {
  return Identity{static_cast<uint64_t>(stat.st_dev), static_cast<uint64_t>(stat.st_ino)};
}

bool SameLifecycleDirectory(int left_fd, int right_fd) {
  struct stat left{};
  struct stat right{};
  return fstat(left_fd, &left) == 0 && fstat(right_fd, &right) == 0 && S_ISDIR(left.st_mode) &&
         S_ISDIR(right.st_mode) && SameIdentity(left, LifecycleIdentityFromStat(right));
}

bool IsExactLifecycleFile(const struct stat& stat, const Identity& expected, mode_t mode,
                          uint64_t expected_size) {
  return S_ISREG(stat.st_mode) && stat.st_nlink == 1 && IsLifecycleOwner(stat) &&
         SameIdentity(stat, expected) && static_cast<mode_t>(stat.st_mode & 07777) == mode &&
         stat.st_size >= 0 && static_cast<uint64_t>(stat.st_size) == expected_size;
}
bool IsBoundedExactLifecycleFile(const struct stat& stat, const Identity& expected, mode_t mode) {
  return S_ISREG(stat.st_mode) && stat.st_nlink == 1 && IsLifecycleOwner(stat) &&
         SameIdentity(stat, expected) && static_cast<mode_t>(stat.st_mode & 07777) == mode &&
         stat.st_size >= 0 && static_cast<uint64_t>(stat.st_size) <= kMaximumLifecycleWriteBytes;
}


bool IsExactLifecycleDirectory(const struct stat& stat, const Identity& expected, mode_t mode) {
  return S_ISDIR(stat.st_mode) && stat.st_nlink >= 2 && IsLifecycleOwner(stat) &&
         SameIdentity(stat, expected) && static_cast<mode_t>(stat.st_mode & 07777) == mode;
}


bool ValidateBoundedLifecycleFileAt(int parent_fd, const std::string& name,
                                    const Identity& expected, mode_t mode) {
  FileDescriptor file(openat(parent_fd, name.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  struct stat opened{};
  struct stat linked{};
  return file.Get() >= 0 && fstat(file.Get(), &opened) == 0 &&
         fstatat(parent_fd, name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         HasSafeAcl(file.Get()) && IsBoundedExactLifecycleFile(opened, expected, mode) &&
         IsBoundedExactLifecycleFile(linked, expected, mode);
}

bool ValidateLifecycleDirectoryAt(int parent_fd, const std::string& name, const Identity& expected,
                                  mode_t mode) {
  FileDescriptor directory(OpenDirectoryAt(parent_fd, name));
  struct stat opened{};
  struct stat linked{};
  return directory.Get() >= 0 && fstat(directory.Get(), &opened) == 0 &&
         fstatat(parent_fd, name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         HasSafeAcl(directory.Get()) && IsExactLifecycleDirectory(opened, expected, mode) &&
         IsExactLifecycleDirectory(linked, expected, mode);
}

bool ValidateLifecycleLinkedDirectory(int parent_fd, const std::string& name, int directory_fd,
                                      const Identity& expected, mode_t mode) {
  struct stat opened{};
  return fstat(directory_fd, &opened) == 0 && HasSafeAcl(directory_fd) &&
         IsExactLifecycleDirectory(opened, expected, mode) &&
         ValidateLifecycleDirectoryAt(parent_fd, name, expected, mode);
}
bool IsEmptyLifecycleDirectory(int directory_fd) {
  const int duplicated_fd = OpenDirectoryAt(directory_fd, ".");
  if (duplicated_fd < 0) {
    return false;
  }
  DIR* directory = fdopendir(duplicated_fd);
  if (directory == nullptr) {
    (void)close(duplicated_fd);
    return false;
  }

  bool empty = true;
  for (;;) {
    errno = 0;
    struct dirent* entry = readdir(directory);
    if (entry == nullptr) {
      empty = errno == 0;
      break;
    }
    if (std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0) {
      empty = false;
      break;
    }
  }
  return closedir(directory) == 0 && empty;
}


bool WriteLifecycleBytes(int fd, uint64_t offset, const SensitiveBytes& bytes) {
  size_t written = 0U;
  while (written < bytes.Size()) {
    const ssize_t count =
        pwrite(fd, bytes.Data() + written, bytes.Size() - written,
               static_cast<off_t>(offset + static_cast<uint64_t>(written)));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return false;
    }
    written += static_cast<size_t>(count);
  }
  return true;
}

bool CreateLifecycleMutationResult(napi_env env, const char* state, const Identity* identity,
                                   napi_value* output) {
  napi_value result;
  napi_value state_value;
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, state, NAPI_AUTO_LENGTH, &state_value)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", state_value))) {
    ThrowLifecycleFailure(env);
    return false;
  }
  if (identity != nullptr) {
    napi_value identity_value;
    napi_value device;
    napi_value inode;
    const std::string device_string = std::to_string(identity->device);
    const std::string inode_string = std::to_string(identity->inode);
    if (!IsNapiStatusOk(napi_create_object(env, &identity_value)) ||
        !IsNapiStatusOk(napi_create_string_utf8(env, device_string.c_str(), NAPI_AUTO_LENGTH,
                                                 &device)) ||
        !IsNapiStatusOk(napi_create_string_utf8(env, inode_string.c_str(), NAPI_AUTO_LENGTH,
                                                 &inode)) ||
        !IsNapiStatusOk(napi_set_named_property(env, identity_value, "device", device)) ||
        !IsNapiStatusOk(napi_set_named_property(env, identity_value, "inode", inode)) ||
        !IsNapiStatusOk(napi_set_named_property(env, result, "identity", identity_value))) {
      ThrowLifecycleFailure(env);
      return false;
    }
  }
  *output = result;
  return true;
}

napi_value LifecycleResult(napi_env env, const char* state) {
  napi_value result;
  return CreateLifecycleMutationResult(env, state, nullptr, &result) ? result : nullptr;
}

bool CreateLifecycleDetailedResult(napi_env env, const char* state, const Identity* target_identity,
                                  const Identity* quarantine_identity, napi_value* output) {
  napi_value result;
  napi_value state_value;
  napi_value target_value;
  napi_value quarantine_value;
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, state, NAPI_AUTO_LENGTH, &state_value)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", state_value))) {
    ThrowLifecycleFailure(env);
    return false;
  }

  const auto create_identity = [env](const Identity* identity, napi_value* value) -> bool {
    if (identity == nullptr) {
      return IsNapiStatusOk(napi_get_null(env, value));
    }
    napi_value result_identity;
    napi_value device;
    napi_value inode;
    const std::string device_string = std::to_string(identity->device);
    const std::string inode_string = std::to_string(identity->inode);
    if (!IsNapiStatusOk(napi_create_object(env, &result_identity)) ||
        !IsNapiStatusOk(napi_create_string_utf8(env, device_string.c_str(), NAPI_AUTO_LENGTH,
                                                 &device)) ||
        !IsNapiStatusOk(napi_create_string_utf8(env, inode_string.c_str(), NAPI_AUTO_LENGTH,
                                                 &inode)) ||
        !IsNapiStatusOk(napi_set_named_property(env, result_identity, "device", device)) ||
        !IsNapiStatusOk(napi_set_named_property(env, result_identity, "inode", inode))) {
      return false;
    }
    *value = result_identity;
    return true;
  };

  if (std::strcmp(state, "completed") == 0 && quarantine_identity != nullptr) {
    if (!create_identity(quarantine_identity, &quarantine_value) ||
        !IsNapiStatusOk(
            napi_set_named_property(env, result, "quarantineIdentity", quarantine_value))) {
      ThrowLifecycleFailure(env);
      return false;
    }
  } else if (std::strcmp(state, "indeterminate") == 0) {
    if (!create_identity(target_identity, &target_value) ||
        !create_identity(quarantine_identity, &quarantine_value) ||
        !IsNapiStatusOk(napi_set_named_property(env, result, "targetIdentity", target_value)) ||
        !IsNapiStatusOk(
            napi_set_named_property(env, result, "quarantineIdentity", quarantine_value))) {
      ThrowLifecycleFailure(env);
      return false;
    }
  }
  *output = result;
  return true;
}


bool LifecycleIdentityAt(int parent_fd, const std::string& name, Identity* output) {
  struct stat stat{};
  if (fstatat(parent_fd, name.c_str(), &stat, AT_SYMLINK_NOFOLLOW) != 0) {
    return false;
  }
  *output = LifecycleIdentityFromStat(stat);
  return true;
}
const napi_type_tag kLifecycleLockTypeTag = {
    0x0e9f4b36aa53f001ULL, 0xb92a1560c17d4e8cULL};

struct LifecycleLock final {
  FileDescriptor parent_fd;
  FileDescriptor file_fd;
  Identity parent_identity;
  Identity identity;
  uint64_t session_generation = 0U;
  std::string name;
  bool released = false;
  bool slot_charged = false;
  FileDescriptor retained_wal_parent_fd;
  FileDescriptor retained_wal_file_fd;
  Identity retained_wal_parent_identity;
  Identity retained_wal_identity;
  uint64_t retained_wal_size = 0U;
  mode_t retained_wal_mode = 0;
  uint64_t retained_wal_session_generation = 0U;
  std::string retained_wal_name;
  std::string retained_wal_digest;
  std::string retained_wal_stat;
  bool retained_wal_active = false;
};
bool ValidateLifecycleParent(const FileDescriptor& parent_fd, const Identity& identity) {
  struct stat parent{};
  return parent_fd.Get() >= 0 && fstat(parent_fd.Get(), &parent) == 0 && S_ISDIR(parent.st_mode) &&
         IsLifecycleDirectoryOwner(parent) && IsSecureMode(parent) && HasSafeAcl(parent_fd.Get()) &&
         SameIdentity(parent, identity);
}
void ClearRetainedLifecycleWal(LifecycleLock* lock) {
  if (lock == nullptr) {
    return;
  }
  lock->retained_wal_file_fd.Reset();
  lock->retained_wal_parent_fd.Reset();
  lock->retained_wal_parent_identity = Identity{};
  lock->retained_wal_identity = Identity{};
  lock->retained_wal_size = 0U;
  lock->retained_wal_mode = 0;
  lock->retained_wal_session_generation = 0U;
  lock->retained_wal_name.clear();
  lock->retained_wal_digest.clear();
  lock->retained_wal_stat.clear();
  lock->retained_wal_active = false;
}

void CloseLifecycleLock(LifecycleLock* lock) {
  if (lock == nullptr || lock->released) {
    return;
  }
  if (lock->file_fd.Get() >= 0) {
    (void)flock(lock->file_fd.Get(), LOCK_UN);
  }
  lock->released = true;
  ClearRetainedLifecycleWal(lock);
  lock->file_fd.Reset();
  lock->parent_fd.Reset();
  if (lock->slot_charged) {
    ReleaseAuthoritySlot(&active_lifecycle_locks);
    lock->slot_charged = false;
  }
}
void FinalizeLifecycleLock(napi_env, void* data, void*) {
  auto* lock = static_cast<LifecycleLock*>(data);
  CloseLifecycleLock(lock);
  delete lock;
}
bool ValidateLifecycleLock(const LifecycleLock* lock) {
  struct stat held{};
  struct stat linked{};
  return lock != nullptr && !lock->released && lock->session_generation != 0U &&
         ValidateLifecycleParent(lock->parent_fd, lock->parent_identity) && lock->file_fd.Get() >= 0 &&
         fstat(lock->file_fd.Get(), &held) == 0 &&
         fstatat(lock->parent_fd.Get(), lock->name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         S_ISREG(held.st_mode) && held.st_nlink == 1 && IsLifecycleOwner(held) &&
         IsCredentialMode(held) && HasSafeAcl(lock->file_fd.Get()) &&
         SameIdentity(held, lock->identity) && SameIdentity(linked, lock->identity) &&
         IsCredentialMode(linked) && linked.st_nlink == 1 && IsLifecycleOwner(linked);
}

bool UnwrapLifecycleLock(napi_env env, napi_value value, LifecycleLock** output) {
  bool tagged = false;
  if (!IsNapiStatusOk(
          napi_check_object_type_tag(env, value, &kLifecycleLockTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowLifecycleDenied(env);
    return false;
  }
  return true;
}
bool RequireLifecycleLock(napi_env env, napi_value value, LifecycleLock** output) {
  if (!UnwrapLifecycleLock(env, value, output)) {
    return false;
  }
  if (!ValidateLifecycleLock(*output)) {
    ThrowLifecycleDenied(env);
    return false;
  }
  return true;
}

bool ParseLifecycleLock(napi_env env, napi_value options, LifecycleLock** output) {
  napi_value value;
  return GetRequiredProperty(env, options, "lock", &value) && RequireLifecycleLock(env, value, output);
}
bool RequireLifecycleLockArgument(napi_env env, napi_callback_info info, LifecycleLock** output) {
  napi_value options;
  return GetSingleObjectArgument(env, info, &options) && ParseLifecycleLock(env, options, output);
}
napi_value LifecycleLockedResult(napi_env env, const LifecycleLock* lock) {
  return LifecycleResult(env, ValidateLifecycleLock(lock) ? "completed" : "indeterminate");
}


napi_value AcquireLifecycleLock(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value path_value;
  std::string path;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "path", &path_value) ||
      !ParseLifecyclePath(env, path_value, &path)) {
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_lifecycle_locks, kMaximumLifecycleLocks)) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }

  FileDescriptor parent;
  std::string name;
  if (!OpenLifecycleParent(env, path, &parent, &name)) {
    ReleaseAuthoritySlot(&active_lifecycle_locks);
    return nullptr;
  }
  FileDescriptor file(openat(parent.Get(), name.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC));
  struct stat parent_stat{};
  struct stat file_stat{};
  if (file.Get() < 0 || fstat(parent.Get(), &parent_stat) != 0 || fstat(file.Get(), &file_stat) != 0 ||
      !S_ISREG(file_stat.st_mode) || file_stat.st_nlink != 1 || !IsLifecycleOwner(file_stat) ||
      !IsCredentialMode(file_stat) || !HasSafeAcl(file.Get()) ||
      !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
      flock(file.Get(), LOCK_EX | LOCK_NB) != 0) {
    ReleaseAuthoritySlot(&active_lifecycle_locks);
    ThrowLifecycleDenied(env);
    return nullptr;
  }

  auto* lock = new (std::nothrow) LifecycleLock{
      .parent_fd = std::move(parent),
      .file_fd = std::move(file),
      .parent_identity = LifecycleIdentityFromStat(parent_stat),
      .identity = LifecycleIdentityFromStat(file_stat),
      .session_generation =
          next_lifecycle_lock_session_generation.fetch_add(1U, std::memory_order_relaxed),
      .name = std::move(name),
      .slot_charged = true,
      .retained_wal_parent_fd = FileDescriptor(),
      .retained_wal_file_fd = FileDescriptor(),
  };
  if (lock == nullptr || lock->session_generation == 0U) {
    if (lock != nullptr) {
      CloseLifecycleLock(lock);
    } else {
      ReleaseAuthoritySlot(&active_lifecycle_locks);
    }
    delete lock;
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  napi_value result;
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, result, &kLifecycleLockTypeTag)) ||
      !IsNapiStatusOk(napi_wrap(env, result, lock, FinalizeLifecycleLock, nullptr, nullptr))) {
    CloseLifecycleLock(lock);
    delete lock;
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  return result;
}

napi_value ReleaseLifecycleLock(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value lock_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "lock", &lock_value)) {
    return nullptr;
  }
  LifecycleLock* lock = nullptr;
  if (!UnwrapLifecycleLock(env, lock_value, &lock)) {
    return nullptr;
  }
  if (lock->released || lock->file_fd.Get() < 0) {
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  if (flock(lock->file_fd.Get(), LOCK_UN) != 0) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  lock->released = true;
  ClearRetainedLifecycleWal(lock);
  lock->file_fd.Reset();
  lock->parent_fd.Reset();
  if (lock->slot_charged) {
    ReleaseAuthoritySlot(&active_lifecycle_locks);
    lock->slot_charged = false;
  }
  return LifecycleResult(env, "completed");
}
napi_value ReleaseLifecycleLockSession(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value lock_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "lock", &lock_value)) {
    return nullptr;
  }
  LifecycleLock* lock = nullptr;
  if (!UnwrapLifecycleLock(env, lock_value, &lock)) {
    return nullptr;
  }
  if (lock->released) {
    return LifecycleResult(env, "completed");
  }
  if (lock->file_fd.Get() < 0) {
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  if (flock(lock->file_fd.Get(), LOCK_UN) != 0) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  lock->released = true;
  ClearRetainedLifecycleWal(lock);
  lock->file_fd.Reset();
  lock->parent_fd.Reset();
  if (lock->slot_charged) {
    ReleaseAuthoritySlot(&active_lifecycle_locks);
    lock->slot_charged = false;
  }
  return LifecycleResult(env, "completed");
}
napi_value RevalidateLifecycleLock(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value lock_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "lock", &lock_value)) {
    return nullptr;
  }
  LifecycleLock* lock = nullptr;
  if (!RequireLifecycleLock(env, lock_value, &lock)) {
    return nullptr;
  }
  return LifecycleLockedResult(env, lock);
}
const napi_type_tag kLifecycleCreationIntentTypeTag = {
    0xb85c0f425e7a19d3ULL, 0x43e7d2f8a9c40b16ULL};
enum class LifecycleCreationIntentKind {
  kCredential,
  kFile,
  kDirectory,
};
constexpr const char* kLifecycleCreationIntentTokenAttribute =
#if defined(__APPLE__)
    "com.scene-glass.lifecycle-creation-intent";
#else
    "user.scene-glass.lifecycle-creation-intent";
#endif

bool IsLowerHexLifecycleToken(const std::string& value, size_t offset, size_t length) {
  if (offset > value.size() || length > value.size() - offset) {
    return false;
  }
  for (size_t index = offset; index < offset + length; ++index) {
    const char character = value[index];
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f'))) {
      return false;
    }
  }
  return true;
}

std::string LifecycleCreationIntentValidationTokenFromMarkerName(const std::string& marker_name) {
  constexpr char kMarkerSuffix[] = ".marker";
  constexpr size_t kIntentTokenBytes = 32U;
  constexpr size_t kSuffixBytes = sizeof(kMarkerSuffix) - 1U;
  if (marker_name.size() <= kIntentTokenBytes + kSuffixBytes ||
      marker_name.compare(marker_name.size() - kSuffixBytes, kSuffixBytes, kMarkerSuffix) != 0) {
    return {};
  }
  const size_t token_offset = marker_name.size() - kSuffixBytes - kIntentTokenBytes;
  if (token_offset == 0U || marker_name[token_offset - 1U] != '-' ||
      !IsLowerHexLifecycleToken(marker_name, token_offset, kIntentTokenBytes)) {
    return {};
  }
  return marker_name.substr(token_offset, kIntentTokenBytes);
}
bool LifecycleCreationIntentPrivateMarkerName(const std::string& marker_name, std::string* output) {
  constexpr char kPrivateSuffix[] = ".private";
  if (output == nullptr || marker_name.empty() ||
      marker_name.size() > kMaximumPathComponentBytes - (sizeof(kPrivateSuffix) - 1U)) {
    return false;
  }
  *output = marker_name + kPrivateSuffix;
  return true;
}

bool SetLifecycleCreationIntentValidationToken(int fd, const std::string& token) {
  if (token.empty()) {
    return true;
  }
#if defined(__APPLE__)
  return fsetxattr(fd, kLifecycleCreationIntentTokenAttribute, const_cast<char*>(token.data()),
                   token.size(), 0, 0) == 0;
#else
  return fsetxattr(fd, kLifecycleCreationIntentTokenAttribute, token.data(), token.size(), 0) == 0;
#endif
}

enum class LifecycleCreationIntentValidationTokenState {
  kMatches,
  kAbsent,
  kMismatched,
};
LifecycleCreationIntentValidationTokenState LifecycleCreationIntentValidationTokenStateForFd(
    int fd, const std::string& token) {
  if (token.empty()) {
    return LifecycleCreationIntentValidationTokenState::kMatches;
  }
  std::array<char, 32U> actual{};
#if defined(__APPLE__)
  const ssize_t length = fgetxattr(fd, kLifecycleCreationIntentTokenAttribute, actual.data(),
                                   actual.size(), 0, 0);
  if (length < 0 && errno == ENOATTR) {
    return LifecycleCreationIntentValidationTokenState::kAbsent;
  }
#else
  const ssize_t length =
      fgetxattr(fd, kLifecycleCreationIntentTokenAttribute, actual.data(), actual.size());
  if (length < 0 && errno == ENODATA) {
    return LifecycleCreationIntentValidationTokenState::kAbsent;
  }
#endif
  return length == static_cast<ssize_t>(token.size()) &&
                 std::memcmp(actual.data(), token.data(), token.size()) == 0
             ? LifecycleCreationIntentValidationTokenState::kMatches
             : LifecycleCreationIntentValidationTokenState::kMismatched;
}
bool MatchesLifecycleCreationIntentValidationToken(int fd, const std::string& token) {
  return LifecycleCreationIntentValidationTokenStateForFd(fd, token) ==
         LifecycleCreationIntentValidationTokenState::kMatches;
}
struct LifecycleCreationIntent final {
  FileDescriptor parent_fd;
  FileDescriptor marker_fd;
  Identity parent_identity;
  Identity marker_identity;
  Identity lock_identity;
  uint64_t lock_session_generation = 0U;
  std::string stage_name;
  std::string marker_name;
  std::string validation_token;
  LifecycleCreationIntentKind kind;
  bool consumed = false;
  bool slot_charged = false;
  bool prepared = false;
};
bool ValidateLifecycleCreationIntentMarker(const FileDescriptor& parent_fd,
                                           const FileDescriptor& marker_fd,
                                           const std::string& name, const Identity& identity,
                                           LifecycleCreationIntentKind kind);
void CloseLifecycleCreationIntent(LifecycleCreationIntent* intent) {
  if (intent == nullptr) {
    return;
  }
  intent->marker_fd.Reset();
  intent->parent_fd.Reset();
  if (intent->slot_charged) {
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    intent->slot_charged = false;
  }
}
void FinalizeLifecycleCreationIntent(napi_env, void* data, void*) {
  auto* intent = static_cast<LifecycleCreationIntent*>(data);
  CloseLifecycleCreationIntent(intent);
  delete intent;
}
bool ValidateLifecycleCreationIntent(const LifecycleCreationIntent* intent,
                                     const LifecycleLock* lock) {
  return intent != nullptr && !intent->consumed && ValidateLifecycleLock(lock) &&
         SameIdentity(intent->lock_identity, lock->identity) &&
         intent->lock_session_generation == lock->session_generation &&
         ValidateLifecycleParent(intent->parent_fd, intent->parent_identity) &&
         MatchesLifecycleCreationIntentValidationToken(intent->marker_fd.Get(), intent->validation_token) &&
         ValidateLifecycleCreationIntentMarker(intent->parent_fd, intent->marker_fd,
                                               intent->marker_name, intent->marker_identity, intent->kind);
}
bool RequireLifecycleCreationIntent(napi_env env, napi_value value, LifecycleCreationIntent** output) {
  bool tagged = false;
  if (!IsNapiStatusOk(
          napi_check_object_type_tag(env, value, &kLifecycleCreationIntentTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowLifecycleDenied(env);
    return false;
  }
  return true;
}
bool LifecycleEntryAbsent(int parent_fd, const std::string& name);
const napi_type_tag kLifecycleStagedFileReservationTypeTag = {
    0x741ac43ef229187bULL, 0x067e981d0d85bc2aULL};

enum class LifecycleStagedFileReservationState {
  kOpen,
  kPublished,
  kClosed,
  kDiscarded,
  kIndeterminate,
};

enum class LifecycleReservationLinkState {
  kMarker,
  kStage,
  kPublished,
};

struct LifecycleStagedFileReservation final {
  FileDescriptor parent_fd;
  FileDescriptor file_fd;
  Identity parent_identity;
  Identity identity;
  Identity lock_identity;
  uint64_t lock_session_generation = 0U;
  std::string name;
  mode_t mode;
  uint64_t size = 0U;
  bool sealed = false;
  uint64_t seal_session_generation = 0U;
  std::string sealed_digest;
  std::string sealed_stat;
  LifecycleReservationLinkState link_state = LifecycleReservationLinkState::kMarker;
  LifecycleStagedFileReservationState state = LifecycleStagedFileReservationState::kOpen;
  bool slot_charged = false;
};
void CloseLifecycleStagedFileReservation(LifecycleStagedFileReservation* reservation) {
  if (reservation == nullptr) {
    return;
  }
  reservation->file_fd.Reset();
  reservation->parent_fd.Reset();
  if (reservation->slot_charged) {
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    reservation->slot_charged = false;
  }
}
bool ValidateLifecycleCreationIntentMarker(const FileDescriptor& parent_fd,
                                           const FileDescriptor& marker_fd,
                                           const std::string& name, const Identity& identity,
                                           LifecycleCreationIntentKind kind) {
  struct stat opened{};
  struct stat linked{};
  if (marker_fd.Get() < 0 || fstat(marker_fd.Get(), &opened) != 0 ||
      fstatat(parent_fd.Get(), name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      !HasSafeAcl(marker_fd.Get())) {
    return false;
  }
  if (kind == LifecycleCreationIntentKind::kDirectory) {
    return IsExactLifecycleDirectory(opened, identity, 0700) &&
           IsExactLifecycleDirectory(linked, identity, 0700);
  }
  return IsExactLifecycleFile(opened, identity, 0600, 0U) &&
         IsExactLifecycleFile(linked, identity, 0600, 0U);
}
void FinalizeLifecycleStagedFileReservation(napi_env, void* data, void*) {
  auto* reservation = static_cast<LifecycleStagedFileReservation*>(data);
  CloseLifecycleStagedFileReservation(reservation);
  delete reservation;
}
bool ValidateLifecycleStagedFileReservationSeal(
    const LifecycleStagedFileReservation* reservation, bool require_stat_snapshot,
    std::string* observed_stat);
bool SealLifecycleStagedFileReservation(LifecycleStagedFileReservation* reservation,
                                        const LifecycleLock* lock);
bool RefreshLifecycleStagedFileReservationSeal(LifecycleStagedFileReservation* reservation,
                                               const LifecycleLock* lock);
bool ValidateLifecycleReservationLink(const FileDescriptor& parent_fd,
                                      const Identity& parent_identity, int entry_fd,
                                      const std::string& name, const Identity& identity,
                                      bool directory) {
  struct stat held{};
  struct stat linked{};
  return ValidateLifecycleParent(parent_fd, parent_identity) && entry_fd >= 0 &&
         fstat(entry_fd, &held) == 0 &&
         fstatat(parent_fd.Get(), name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         SameIdentity(held, identity) && SameIdentity(linked, identity) && IsLifecycleOwner(held) &&
         (directory ? (S_ISDIR(held.st_mode) && held.st_nlink >= 2 && S_ISDIR(linked.st_mode) &&
                       linked.st_nlink >= 2)
                    : (S_ISREG(held.st_mode) && held.st_nlink == 1 && S_ISREG(linked.st_mode) &&
                       linked.st_nlink == 1));
}
bool ValidateLifecycleCreationIntentAuthority(const LifecycleCreationIntent* intent,
                                              const LifecycleLock* lock) {
  return intent != nullptr && !intent->consumed && ValidateLifecycleLock(lock) &&
         SameIdentity(intent->lock_identity, lock->identity) &&
         intent->lock_session_generation == lock->session_generation &&
         ValidateLifecycleReservationLink(
             intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
             intent->marker_name, intent->marker_identity,
             intent->kind == LifecycleCreationIntentKind::kDirectory);
}
bool RefreshLifecycleCreationIntentAuthority(LifecycleCreationIntent* intent,
                                             const LifecycleLock* lock) {
  if (intent == nullptr || intent->consumed || !ValidateLifecycleLock(lock) ||
      !SameIdentity(intent->lock_identity, lock->identity) ||
      intent->lock_session_generation != lock->session_generation ||
      !ValidateLifecycleParent(intent->parent_fd, intent->parent_identity) ||
      intent->marker_fd.Get() < 0) {
    return false;
  }
  struct stat held{};
  struct stat linked{};
  if (fstat(intent->marker_fd.Get(), &held) != 0 ||
      fstatat(intent->parent_fd.Get(), intent->marker_name.c_str(), &linked,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameIdentity(held, LifecycleIdentityFromStat(linked)) || !IsLifecycleOwner(held) ||
      (intent->kind == LifecycleCreationIntentKind::kDirectory
           ? (!S_ISDIR(held.st_mode) || held.st_nlink < 2)
           : (!S_ISREG(held.st_mode) || held.st_nlink != 1))) {
    return false;
  }
  intent->marker_identity = LifecycleIdentityFromStat(held);
  return ValidateLifecycleCreationIntentAuthority(intent, lock);
}
bool DiscardLifecycleReservationLink(const FileDescriptor& parent, const Identity& parent_identity,
                                     int entry_fd, const std::string& name,
                                     const Identity& identity, bool is_directory,
                                     const LifecycleLock* lock) {
  struct stat held{};
  struct stat linked{};
  if (parent.Get() < 0 || entry_fd < 0 || name.empty() ||
      !ValidateLifecycleParent(parent, parent_identity) || fstat(entry_fd, &held) != 0 ||
      !SameIdentity(held, identity) ||
      fstatat(parent.Get(), name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameFileState(held, linked) || !ValidateLifecycleLock(lock)) {
    return false;
  }
  if (is_directory) {
    if (!S_ISDIR(held.st_mode) || !IsEmptyLifecycleDirectory(entry_fd)) {
      return false;
    }
  } else if (!S_ISREG(held.st_mode)) {
    return false;
  }
  if (unlinkat(parent.Get(), name.c_str(), is_directory ? AT_REMOVEDIR : 0) != 0) {
    return false;
  }
  return LifecycleEntryAbsent(parent.Get(), name) && fsync(parent.Get()) == 0 &&
         ValidateLifecycleLock(lock);
}
bool ValidateLifecycleStagedFileReservation(const LifecycleStagedFileReservation* reservation) {
  struct stat held{};
  struct stat linked{};
  return reservation != nullptr &&
         (reservation->link_state == LifecycleReservationLinkState::kStage ||
          reservation->link_state == LifecycleReservationLinkState::kPublished) &&
         ValidateLifecycleReservationLink(reservation->parent_fd, reservation->parent_identity,
                                          reservation->file_fd.Get(), reservation->name,
                                          reservation->identity, false) &&
         fstat(reservation->file_fd.Get(), &held) == 0 &&
         fstatat(reservation->parent_fd.Get(), reservation->name.c_str(), &linked,
                 AT_SYMLINK_NOFOLLOW) == 0 &&
         HasSafeAcl(reservation->file_fd.Get()) &&
         IsExactLifecycleFile(held, reservation->identity, reservation->mode, reservation->size) &&
         IsExactLifecycleFile(linked, reservation->identity, reservation->mode, reservation->size) &&
         (!reservation->sealed ||
          (reservation->seal_session_generation == reservation->lock_session_generation &&
           ValidateLifecycleStagedFileReservationSeal(reservation, true, nullptr)));
}
bool ValidateLifecycleStagedFileReservationLock(
    const LifecycleStagedFileReservation* reservation, const LifecycleLock* lock) {
  return reservation != nullptr && ValidateLifecycleLock(lock) &&
         SameIdentity(lock->identity, reservation->lock_identity) &&
         lock->session_generation == reservation->lock_session_generation;
}
bool ParseLifecycleStagedFileReservation(napi_env env, napi_value options,
                                         LifecycleStagedFileReservation** output);

napi_value SyncLifecycleStagedFileReservation(napi_env env, napi_callback_info info) {
  napi_value options;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state != LifecycleStagedFileReservationState::kPublished ||
      reservation->link_state != LifecycleReservationLinkState::kPublished ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  if (fsync(reservation->file_fd.Get()) != 0 ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock) ||
      fsync(reservation->parent_fd.Get()) != 0 ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}



bool RequireLifecycleStagedFileReservation(napi_env env, napi_value value,
                                           LifecycleStagedFileReservation** output) {
  bool tagged = false;
  if (!IsNapiStatusOk(napi_check_object_type_tag(env, value,
                                                  &kLifecycleStagedFileReservationTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowLifecycleDenied(env);
    return false;
  }
  return true;
}

bool ParseLifecycleStagedFileReservation(napi_env env, napi_value options,
                                         LifecycleStagedFileReservation** output) {
  napi_value value;
  return GetRequiredProperty(env, options, "reservation", &value) &&
         RequireLifecycleStagedFileReservation(env, value, output);
}

const napi_type_tag kLifecycleStagedDirectoryReservationTypeTag = {
    0xc631fd5e72a40bc9ULL, 0x3d5887be1e5ac704ULL};

enum class LifecycleStagedDirectoryReservationState {
  kOpen,
  kPublished,
  kClosed,
  kDiscarded,
  kIndeterminate,
};

struct LifecycleStagedDirectoryReservation final {
  FileDescriptor parent_fd;
  FileDescriptor directory_fd;
  Identity parent_identity;
  Identity identity;
  Identity lock_identity;
  uint64_t lock_session_generation = 0U;
  std::string name;
  mode_t mode;
  LifecycleReservationLinkState link_state = LifecycleReservationLinkState::kMarker;
  LifecycleStagedDirectoryReservationState state =
      LifecycleStagedDirectoryReservationState::kOpen;
  bool slot_charged = false;
};
void CloseLifecycleStagedDirectoryReservation(LifecycleStagedDirectoryReservation* reservation) {
  if (reservation == nullptr) {
    return;
  }
  reservation->directory_fd.Reset();
  reservation->parent_fd.Reset();
  if (reservation->slot_charged) {
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    reservation->slot_charged = false;
  }
}
void FinalizeLifecycleStagedDirectoryReservation(napi_env, void* data, void*) {
  auto* reservation = static_cast<LifecycleStagedDirectoryReservation*>(data);
  CloseLifecycleStagedDirectoryReservation(reservation);
  delete reservation;
}
bool ValidateLifecycleStagedDirectoryReservation(
    const LifecycleStagedDirectoryReservation* reservation) {
  struct stat held{};
  struct stat linked{};
  return reservation != nullptr &&
         (reservation->link_state == LifecycleReservationLinkState::kStage ||
          reservation->link_state == LifecycleReservationLinkState::kPublished) &&
         ValidateLifecycleReservationLink(reservation->parent_fd, reservation->parent_identity,
                                          reservation->directory_fd.Get(), reservation->name,
                                          reservation->identity, true) &&
         fstat(reservation->directory_fd.Get(), &held) == 0 &&
         fstatat(reservation->parent_fd.Get(), reservation->name.c_str(), &linked,
                 AT_SYMLINK_NOFOLLOW) == 0 &&
         HasSafeAcl(reservation->directory_fd.Get()) &&
         IsExactLifecycleDirectory(held, reservation->identity, reservation->mode) &&
         IsExactLifecycleDirectory(linked, reservation->identity, reservation->mode);
}
bool ValidateLifecycleStagedDirectoryReservationLock(
    const LifecycleStagedDirectoryReservation* reservation, const LifecycleLock* lock) {
  return reservation != nullptr && ValidateLifecycleLock(lock) &&
         SameIdentity(lock->identity, reservation->lock_identity) &&
         lock->session_generation == reservation->lock_session_generation;
}
bool ParseLifecycleStagedDirectoryReservation(napi_env env, napi_value options,
                                              LifecycleStagedDirectoryReservation** output);
napi_value SyncLifecycleStagedDirectoryReservation(napi_env env, napi_callback_info info) {
  napi_value options;
  LifecycleStagedDirectoryReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedDirectoryReservation(env, options, &reservation) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state != LifecycleStagedDirectoryReservationState::kPublished ||
      reservation->link_state != LifecycleReservationLinkState::kPublished ||
      !ValidateLifecycleStagedDirectoryReservation(reservation) ||
      !ValidateLifecycleStagedDirectoryReservationLock(reservation, lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  if (fsync(reservation->directory_fd.Get()) != 0 ||
      !ValidateLifecycleStagedDirectoryReservation(reservation) ||
      !ValidateLifecycleStagedDirectoryReservationLock(reservation, lock) ||
      fsync(reservation->parent_fd.Get()) != 0 ||
      !ValidateLifecycleStagedDirectoryReservation(reservation) ||
      !ValidateLifecycleStagedDirectoryReservationLock(reservation, lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}


bool RequireLifecycleStagedDirectoryReservation(napi_env env, napi_value value,
                                                LifecycleStagedDirectoryReservation** output) {
  bool tagged = false;
  if (!IsNapiStatusOk(
          napi_check_object_type_tag(env, value, &kLifecycleStagedDirectoryReservationTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowLifecycleDenied(env);
    return false;
  }
  return true;
}

bool ParseLifecycleStagedDirectoryReservation(napi_env env, napi_value options,
                                              LifecycleStagedDirectoryReservation** output) {
  napi_value value;
  return GetRequiredProperty(env, options, "reservation", &value) &&
         RequireLifecycleStagedDirectoryReservation(env, value, output);
}

const napi_type_tag kLifecycleQuarantineTypeTag = {
    0x918667d75251b2c3ULL, 0x49ea1d7e6b2f870aULL};

enum class LifecycleQuarantineKind {
  kFile,
  kDirectory,
};

enum class LifecycleQuarantineOperation {
  kMove,
  kExchange,
};

enum class LifecycleQuarantineState {
  kActive,
  kFinalized,
  kRestored,
  kIndeterminate,
};
enum class LifecycleQuarantinePhase {
  kPrepared,
  kAtQuarantine,
  kAtTarget,
  kUnlinked,
};

struct LifecycleQuarantine final {
  FileDescriptor parent_fd;
  FileDescriptor entry_fd;
  Identity parent_identity;
  Identity lock_identity;
  uint64_t lock_session_generation = 0U;
  std::string target_name;
  std::string quarantine_name;
  Identity target_identity;
  Identity quarantine_identity;
  mode_t target_mode;
  mode_t quarantine_mode;
  LifecycleQuarantineKind kind;
  LifecycleQuarantineOperation operation;
  bool has_content_snapshot = false;
  uint64_t expected_size = 0U;
  std::string expected_digest;
  bool has_stat_snapshot = false;
  std::string expected_stat;
  LifecycleQuarantineState state = LifecycleQuarantineState::kActive;
  LifecycleQuarantinePhase phase = LifecycleQuarantinePhase::kPrepared;
  bool slot_charged = false;
};
void CloseLifecycleQuarantine(LifecycleQuarantine* quarantine) {
  if (quarantine == nullptr) {
    return;
  }
  quarantine->parent_fd.Reset();
  quarantine->entry_fd.Reset();
  if (quarantine->slot_charged) {
    ReleaseAuthoritySlot(&active_lifecycle_quarantines);
    quarantine->slot_charged = false;
  }
}
void FinalizeLifecycleQuarantine(napi_env, void* data, void*) {
  auto* quarantine = static_cast<LifecycleQuarantine*>(data);
  CloseLifecycleQuarantine(quarantine);
  delete quarantine;
}
struct LifecycleExactFileRecord;
bool BindRetainedLifecycleQuarantineExactSnapshot(LifecycleQuarantine* quarantine,
                                                   const LifecycleExactFileRecord& target,
                                                   const LifecycleLock* lock);
bool ValidateRetainedLifecycleQuarantineExactSnapshot(const LifecycleQuarantine* quarantine,
                                                       const LifecycleLock* lock);

bool CreateLifecycleQuarantine(napi_env env, const LifecycleLock* lock, FileDescriptor* parent,
                               const std::string& target_name, const std::string& quarantine_name,
                               const Identity& target_identity, const Identity& quarantine_identity,
                               mode_t target_mode, mode_t quarantine_mode, LifecycleQuarantineKind kind,
                               LifecycleQuarantineOperation operation, LifecycleQuarantine** output,
                               napi_value* value) {
  struct stat parent_stat{};
  if (lock == nullptr || !ValidateLifecycleLock(lock) || parent == nullptr || parent->Get() < 0 ||
      fstat(parent->Get(), &parent_stat) != 0 ||
      !ValidateLifecycleParent(*parent, LifecycleIdentityFromStat(parent_stat)) ||
      !(kind == LifecycleQuarantineKind::kFile
            ? ValidateBoundedLifecycleFileAt(parent->Get(), target_name, quarantine_identity,
                                              quarantine_mode)
            : ValidateLifecycleDirectoryAt(parent->Get(), target_name, quarantine_identity,
                                           quarantine_mode))) {
    ThrowLifecycleFailure(env);
    return false;
  }
  FileDescriptor entry(kind == LifecycleQuarantineKind::kDirectory
                           ? OpenDirectoryAt(parent->Get(), target_name)
                           : OpenFinalAt(parent->Get(), target_name));
  struct stat entry_stat{};
  if (entry.Get() < 0 || fstat(entry.Get(), &entry_stat) != 0 ||
      !SameIdentity(entry_stat, quarantine_identity) || !HasSafeAcl(entry.Get())) {
    ThrowLifecycleFailure(env);
    return false;
  }
  if (!TryAcquireAuthoritySlot(&active_lifecycle_quarantines, kMaximumLifecycleQuarantines)) {
    ThrowLifecycleFailure(env);
    return false;
  }
  auto* quarantine = new (std::nothrow) LifecycleQuarantine{
      .parent_fd = FileDescriptor(parent->Release()),
      .entry_fd = std::move(entry),
      .parent_identity = LifecycleIdentityFromStat(parent_stat),
      .lock_identity = lock->identity,
      .lock_session_generation = lock->session_generation,
      .target_name = target_name,
      .quarantine_name = quarantine_name,
      .target_identity = target_identity,
      .quarantine_identity = quarantine_identity,
      .target_mode = target_mode,
      .quarantine_mode = quarantine_mode,
      .kind = kind,
      .operation = operation,
      .slot_charged = true,
  };
  if (quarantine == nullptr) {
    ReleaseAuthoritySlot(&active_lifecycle_quarantines);
    ThrowLifecycleFailure(env);
    return false;
  }

  napi_value result;
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, result, &kLifecycleQuarantineTypeTag)) ||
      !IsNapiStatusOk(
          napi_wrap(env, result, quarantine, FinalizeLifecycleQuarantine, nullptr, nullptr))) {
    CloseLifecycleQuarantine(quarantine);
    delete quarantine;
    ThrowLifecycleFailure(env);
    return false;
  }

  *output = quarantine;
  *value = result;
  return true;
}

bool RequireLifecycleQuarantine(napi_env env, napi_value value, LifecycleQuarantine** output) {
  bool tagged = false;
  if (!IsNapiStatusOk(
          napi_check_object_type_tag(env, value, &kLifecycleQuarantineTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowLifecycleDenied(env);
    return false;
  }
  return true;
}

bool ValidateLifecycleQuarantineParent(const LifecycleQuarantine* quarantine) {
  return quarantine != nullptr &&
         ValidateLifecycleParent(quarantine->parent_fd, quarantine->parent_identity);
}
bool ValidateLifecycleQuarantineLock(const LifecycleQuarantine* quarantine,
                                     const LifecycleLock* lock) {
  return quarantine != nullptr && ValidateLifecycleLock(lock) &&
         SameIdentity(quarantine->lock_identity, lock->identity) &&
         quarantine->lock_session_generation == lock->session_generation;
}

bool ValidateLifecycleQuarantineEntry(const LifecycleQuarantine* quarantine,
                                      const std::string& name, const Identity& identity,
                                      mode_t mode) {
  if (!ValidateLifecycleQuarantineParent(quarantine)) {
    return false;
  }
  return quarantine->kind == LifecycleQuarantineKind::kFile
             ? ValidateBoundedLifecycleFileAt(quarantine->parent_fd.Get(), name, identity, mode)
             : ValidateLifecycleDirectoryAt(quarantine->parent_fd.Get(), name, identity, mode);
}
bool ValidateRetainedLifecycleQuarantineEntry(const LifecycleQuarantine* quarantine,
                                              const LifecycleLock* lock) {
  if (quarantine == nullptr || quarantine->entry_fd.Get() < 0) {
    return false;
  }
  struct stat held{};
  return fstat(quarantine->entry_fd.Get(), &held) == 0 &&
         SameIdentity(held, quarantine->quarantine_identity) &&
         ValidateLifecycleQuarantineEntry(quarantine, quarantine->quarantine_name,
                                          quarantine->quarantine_identity,
                                          quarantine->quarantine_mode) &&
         ValidateRetainedLifecycleQuarantineExactSnapshot(quarantine, lock);
}

bool LifecycleQuarantineEntryIdentity(const LifecycleQuarantine* quarantine,
                                      const std::string& name, Identity* output) {
  if (!ValidateLifecycleQuarantineParent(quarantine)) {
    return false;
  }
  return LifecycleIdentityAt(quarantine->parent_fd.Get(), name, output);
}

napi_value LifecycleQuarantineDetailedResult(napi_env env, const char* state,
                                             const Identity* target_identity,
                                             const Identity* quarantine_identity,
                                             napi_value quarantine_value) {
  napi_value result;
  if (!CreateLifecycleDetailedResult(env, state, target_identity, quarantine_identity, &result) ||
      !IsNapiStatusOk(
          napi_set_named_property(env, result, "quarantine", quarantine_value))) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  return result;
}

napi_value LifecycleQuarantineIndeterminate(napi_env env, LifecycleQuarantine* quarantine,
                                            napi_value quarantine_value) {
  Identity observed_target{};
  Identity observed_quarantine{};
  const Identity* target_identity =
      LifecycleQuarantineEntryIdentity(quarantine, quarantine->target_name, &observed_target)
          ? &observed_target
          : nullptr;
  const Identity* quarantine_identity =
      LifecycleQuarantineEntryIdentity(quarantine, quarantine->quarantine_name, &observed_quarantine)
          ? &observed_quarantine
          : nullptr;
  struct stat held{};
  if (quarantine != nullptr && fstat(quarantine->entry_fd.Get(), &held) == 0 &&
      SameIdentity(held, quarantine->quarantine_identity)) {
    if (ValidateLifecycleQuarantineEntry(quarantine, quarantine->quarantine_name,
                                         quarantine->quarantine_identity,
                                         quarantine->quarantine_mode)) {
      quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
    } else if (
        quarantine->operation == LifecycleQuarantineOperation::kMove &&
        ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                         quarantine->quarantine_identity,
                                         quarantine->quarantine_mode) &&
        LifecycleEntryAbsent(quarantine->parent_fd.Get(), quarantine->quarantine_name)) {
      quarantine->phase = LifecycleQuarantinePhase::kAtTarget;
    } else if (
        quarantine->operation == LifecycleQuarantineOperation::kExchange &&
        ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                         quarantine->quarantine_identity,
                                         quarantine->quarantine_mode) &&
        ValidateLifecycleQuarantineEntry(quarantine, quarantine->quarantine_name,
                                         quarantine->target_identity,
                                         quarantine->target_mode)) {
      quarantine->phase = LifecycleQuarantinePhase::kAtTarget;
    }
  }
  quarantine->state = LifecycleQuarantineState::kIndeterminate;
  return LifecycleQuarantineDetailedResult(env, "indeterminate", target_identity, quarantine_identity,
                                           quarantine_value);
}

bool ParseLifecycleQuarantineHandle(napi_env env, napi_callback_info info, napi_value* output) {
  napi_value options;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, "quarantine", output);
}

enum class LifecycleExchangeResult {
  kCompleted,
  kUnsupported,
  kFailed,
};

LifecycleExchangeResult ExchangeLifecycleEntries(int parent_fd, const std::string& source_name,
                                                 const std::string& target_name) {
#if defined(__APPLE__)
  if (renameatx_np(parent_fd, source_name.c_str(), parent_fd, target_name.c_str(), RENAME_SWAP) ==
      0) {
    return LifecycleExchangeResult::kCompleted;
  }
#elif defined(__linux__)
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1U)
#endif
  if (syscall(SYS_renameat2, parent_fd, source_name.c_str(), parent_fd, target_name.c_str(),
              RENAME_EXCHANGE) == 0) {
    return LifecycleExchangeResult::kCompleted;
  }
#endif
  const int error = errno;
  if (error == ENOSYS || error == EOPNOTSUPP || error == EINVAL) {
    return LifecycleExchangeResult::kUnsupported;
  }
  return LifecycleExchangeResult::kFailed;
}

enum class LifecycleNoReplaceResult {
  kCompleted,
  kUnsupported,
  kFailed,
};

LifecycleNoReplaceResult RenameLifecycleNoReplace(int parent_fd, const std::string& source_name,
                                                  const std::string& target_name) {
#if defined(__APPLE__)
  if (renameatx_np(parent_fd, source_name.c_str(), parent_fd, target_name.c_str(), RENAME_EXCL) ==
      0) {
    return LifecycleNoReplaceResult::kCompleted;
  }
#elif defined(__linux__)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0U)
#endif
  if (syscall(SYS_renameat2, parent_fd, source_name.c_str(), parent_fd, target_name.c_str(),
              RENAME_NOREPLACE) == 0) {
    return LifecycleNoReplaceResult::kCompleted;
  }
#endif
  const int error = errno;
  if (error == ENOSYS || error == EOPNOTSUPP || error == EINVAL) {
    return LifecycleNoReplaceResult::kUnsupported;
  }
  return LifecycleNoReplaceResult::kFailed;
}
bool LifecycleEntryAbsent(int parent_fd, const std::string& name);

bool ValidateExactLifecycleEntryAt(int parent_fd, const std::string& name, const Identity& identity,
                                   mode_t mode, LifecycleQuarantineKind kind) {
  return kind == LifecycleQuarantineKind::kFile
             ? ValidateBoundedLifecycleFileAt(parent_fd, name, identity, mode)
             : ValidateLifecycleDirectoryAt(parent_fd, name, identity, mode);
}

enum class LifecycleExactMoveResult {
  kCompleted,
  kRestoredForeign,
  kIndeterminate,
};

LifecycleExactMoveResult MoveExactLifecycleEntryToQuarantine(
    int parent_fd, const std::string& source_name, const std::string& quarantine_name,
    const Identity& identity, mode_t mode, LifecycleQuarantineKind kind, const LifecycleLock* lock) {
  if (!ValidateExactLifecycleEntryAt(parent_fd, source_name, identity, mode, kind) ||
      !ValidateLifecycleLock(lock)) {
    return LifecycleExactMoveResult::kIndeterminate;
  }
  if (RenameLifecycleNoReplace(parent_fd, source_name, quarantine_name) !=
      LifecycleNoReplaceResult::kCompleted) {
    return LifecycleExactMoveResult::kIndeterminate;
  }
  if (ValidateExactLifecycleEntryAt(parent_fd, quarantine_name, identity, mode, kind) &&
      LifecycleEntryAbsent(parent_fd, source_name) && fsync(parent_fd) == 0 &&
      ValidateLifecycleLock(lock)) {
    return LifecycleExactMoveResult::kCompleted;
  }

  Identity moved_identity{};
  if (!LifecycleEntryAbsent(parent_fd, source_name) ||
      !LifecycleIdentityAt(parent_fd, quarantine_name, &moved_identity) ||
      RenameLifecycleNoReplace(parent_fd, quarantine_name, source_name) !=
          LifecycleNoReplaceResult::kCompleted ||
      !LifecycleEntryAbsent(parent_fd, quarantine_name) ||
      !ValidateExactLifecycleEntryAt(parent_fd, source_name, moved_identity, mode, kind) ||
      fsync(parent_fd) != 0 || !ValidateLifecycleLock(lock)) {
    return LifecycleExactMoveResult::kIndeterminate;
  }
  return LifecycleExactMoveResult::kRestoredForeign;
}
bool ParseLifecycleNoReplaceOptions(napi_env env, napi_callback_info info, std::string* staging_path,
                                    std::string* target_path, Identity* identity, mode_t* mode) {
  napi_value options;
  napi_value staging_path_value;
  napi_value target_path_value;
  napi_value identity_value;
  napi_value mode_value;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, "stagingPath", &staging_path_value) &&
         GetRequiredProperty(env, options, "targetPath", &target_path_value) &&
         GetRequiredProperty(env, options, "identity", &identity_value) &&
         GetRequiredProperty(env, options, "mode", &mode_value) &&
         ParseLifecyclePath(env, staging_path_value, staging_path) &&
         ParseLifecyclePath(env, target_path_value, target_path) &&
         ParseIdentity(env, identity_value, identity) && ParseLifecycleMode(env, mode_value, mode);
}

bool ParseLifecycleReplaceOptions(napi_env env, napi_callback_info info, std::string* staging_path,
                                  std::string* target_path, Identity* identity, mode_t* mode,
                                  Identity* target_identity, mode_t* target_mode) {
  napi_value options;
  napi_value staging_path_value;
  napi_value target_path_value;
  napi_value identity_value;
  napi_value mode_value;
  napi_value target_identity_value;
  napi_value target_mode_value;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, "stagingPath", &staging_path_value) &&
         GetRequiredProperty(env, options, "targetPath", &target_path_value) &&
         GetRequiredProperty(env, options, "identity", &identity_value) &&
         GetRequiredProperty(env, options, "mode", &mode_value) &&
         GetRequiredProperty(env, options, "targetIdentity", &target_identity_value) &&
         GetRequiredProperty(env, options, "targetMode", &target_mode_value) &&
         ParseLifecyclePath(env, staging_path_value, staging_path) &&
         ParseLifecyclePath(env, target_path_value, target_path) &&
         ParseIdentity(env, identity_value, identity) && ParseLifecycleMode(env, mode_value, mode) &&
         ParseIdentity(env, target_identity_value, target_identity) &&
         ParseLifecycleMode(env, target_mode_value, target_mode);
}

bool ParseLifecycleQuarantineOptions(napi_env env, napi_callback_info info, std::string* path,
                                     std::string* quarantine_path, Identity* identity, mode_t* mode) {
  napi_value options;
  napi_value path_value;
  napi_value quarantine_path_value;
  napi_value identity_value;
  napi_value mode_value;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, "path", &path_value) &&
         GetRequiredProperty(env, options, "quarantinePath", &quarantine_path_value) &&
         GetRequiredProperty(env, options, "identity", &identity_value) &&
         GetRequiredProperty(env, options, "mode", &mode_value) &&
         ParseLifecyclePath(env, path_value, path) &&
         ParseLifecyclePath(env, quarantine_path_value, quarantine_path) &&
         ParseIdentity(env, identity_value, identity) && ParseLifecycleMode(env, mode_value, mode);
}
struct LifecycleExactFileRecord {
  std::string path;
  Identity identity;
  mode_t mode = 0;
  bool has_content_snapshot = false;
  uint64_t expected_size = 0U;
  std::string expected_digest;
  bool has_stat_snapshot = false;
  std::string expected_stat;
};
bool IsSha256Digest(const std::string& value) {
  if (value.size() != 71U || value.compare(0U, 7U, "sha256:") != 0) {
    return false;
  }
  return IsLowerHexLifecycleToken(value, 7U, 64U);
}
bool ParseLifecycleExactFileRecord(napi_env env, napi_value value,
                                   LifecycleExactFileRecord* output) {
  napi_value file;
  napi_value path;
  napi_value identity;
  napi_value mode;
  return GetObject(env, value, &file) && GetRequiredProperty(env, file, "path", &path) &&
         GetRequiredProperty(env, file, "identity", &identity) &&
         GetRequiredProperty(env, file, "mode", &mode) &&
         ParseLifecyclePath(env, path, &output->path) &&
         ParseIdentity(env, identity, &output->identity) &&
         ParseLifecycleMode(env, mode, &output->mode);
}
bool ParseLifecycleExactContentSnapshot(napi_env env, napi_value value,
                                        LifecycleExactFileRecord* output) {
  napi_value file;
  napi_value size;
  napi_value digest;
  uint32_t expected_size = 0U;
  if (!GetObject(env, value, &file) || !GetRequiredProperty(env, file, "size", &size) ||
      !GetRequiredProperty(env, file, "digest", &digest) ||
      !ParseLifecycleSize(env, size, &expected_size) ||
      !GetString(env, digest, &output->expected_digest, 71U) ||
      !IsSha256Digest(output->expected_digest)) {
    return false;
  }
  output->has_content_snapshot = true;
  output->expected_size = expected_size;
  return true;
}
bool ParseLifecycleExactWalSnapshot(napi_env env, napi_value value,
                                    LifecycleExactFileRecord* output) {
  napi_value file;
  napi_value stat;
  return ParseLifecycleExactContentSnapshot(env, value, output) && GetObject(env, value, &file) &&
         GetRequiredProperty(env, file, "stat", &stat) &&
         GetString(env, stat, &output->expected_stat, 256U) && !output->expected_stat.empty() &&
         (output->has_stat_snapshot = true);
}

bool ParseExactLifecycleAuthorityOptions(napi_env env, napi_callback_info info,
                                         LifecycleExactFileRecord* target, LifecycleLock** lock) {
  napi_value options;
  napi_value target_value;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, "target", &target_value) &&
         ParseLifecycleExactFileRecord(env, target_value, target) && ParseLifecycleLock(env, options, lock);
}
bool OpenExactLifecycleFile(napi_env env, const LifecycleExactFileRecord& target,
                            FileDescriptor* parent, std::string* name, FileDescriptor* file,
                            struct stat* opened, struct stat* linked) {
  if (parent == nullptr || name == nullptr || file == nullptr || opened == nullptr || linked == nullptr ||
      !OpenLifecycleParent(env, target.path, parent, name)) {
    return false;
  }
  file->Reset(OpenFinalAt(parent->Get(), *name));
  return file->Get() >= 0 && fstat(file->Get(), opened) == 0 &&
         fstatat(parent->Get(), name->c_str(), linked, AT_SYMLINK_NOFOLLOW) == 0;
}
napi_value ValidateExactCredential(napi_env env, napi_callback_info info) {
  LifecycleExactFileRecord target{};
  LifecycleLock* lock = nullptr;
  if (!ParseExactLifecycleAuthorityOptions(env, info, &target, &lock)) {
    return nullptr;
  }
  FileDescriptor parent;
  std::string name;
  FileDescriptor file;
  struct stat parent_stat{};
  struct stat opened{};
  struct stat linked{};
  if (target.mode != 0600 ||
      !OpenExactLifecycleFile(env, target, &parent, &name, &file, &opened, &linked) ||
      fstat(parent.Get(), &parent_stat) != 0 ||
      !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
      !HasSafeAcl(file.Get()) ||
      !IsBoundedExactLifecycleFile(opened, target.identity, target.mode) ||
      !IsBoundedExactLifecycleFile(linked, target.identity, target.mode) ||
      !ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}
napi_value ValidateExactDirectory(napi_env env, napi_callback_info info) {
  LifecycleExactFileRecord target{};
  LifecycleLock* lock = nullptr;
  if (!ParseExactLifecycleAuthorityOptions(env, info, &target, &lock)) {
    return nullptr;
  }
  FileDescriptor parent;
  std::string name;
  if (!OpenLifecycleParent(env, target.path, &parent, &name) ||
      !ValidateLifecycleDirectoryAt(parent.Get(), name, target.identity, target.mode) ||
      !ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}
bool CreateExactLifecycleWalReadResult(napi_env env, const SensitiveBytes& bytes,
                                       const struct stat& stat, napi_value* output) {
  napi_value result;
  napi_value state;
  napi_value content;
  void* copied = nullptr;
  napi_value identity;
  napi_value device;
  napi_value inode;
  napi_value size;
  napi_value digest;
  napi_value stat_snapshot;
  const std::string device_string = std::to_string(static_cast<uint64_t>(stat.st_dev));
  const std::string inode_string = std::to_string(static_cast<uint64_t>(stat.st_ino));
  const std::string content_digest = Sha256Digest(bytes);
  const std::string stat_snapshot_string = LifecycleStatSnapshot(stat);
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, "completed", NAPI_AUTO_LENGTH, &state)) ||
      !IsNapiStatusOk(
          napi_create_buffer_copy(env, bytes.Size(), bytes.Size() == 0U ? nullptr : bytes.Data(),
                                  &copied, &content)) ||
      !IsNapiStatusOk(napi_create_object(env, &identity)) ||
      !IsNapiStatusOk(
          napi_create_string_utf8(env, device_string.c_str(), NAPI_AUTO_LENGTH, &device)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, inode_string.c_str(), NAPI_AUTO_LENGTH, &inode)) ||
      !IsNapiStatusOk(napi_create_uint32(env, static_cast<uint32_t>(bytes.Size()), &size)) ||
      !IsNapiStatusOk(
          napi_create_string_utf8(env, content_digest.c_str(), NAPI_AUTO_LENGTH, &digest)) ||
      !IsNapiStatusOk(
          napi_create_string_utf8(env, stat_snapshot_string.c_str(), NAPI_AUTO_LENGTH,
                                  &stat_snapshot)) ||
      !IsNapiStatusOk(napi_set_named_property(env, identity, "device", device)) ||
      !IsNapiStatusOk(napi_set_named_property(env, identity, "inode", inode)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", state)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "bytes", content)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "identity", identity)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "size", size)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "digest", digest)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "stat", stat_snapshot))) {
    ZeroizeMemory(copied, bytes.Size());
    ThrowLifecycleFailure(env);
    return false;
  }
  *output = result;
  return true;
}
napi_value ReadExactLifecycleWal(napi_env env, napi_callback_info info) {
  LifecycleExactFileRecord target{};
  LifecycleLock* lock = nullptr;
  if (!ParseExactLifecycleAuthorityOptions(env, info, &target, &lock)) {
    return nullptr;
  }
  ClearRetainedLifecycleWal(lock);
  FileDescriptor parent;
  std::string name;
  FileDescriptor file;
  struct stat parent_stat{};
  struct stat opened{};
  struct stat linked{};
  if (target.mode != 0600 ||
      !OpenExactLifecycleFile(env, target, &parent, &name, &file, &opened, &linked) ||
      fstat(parent.Get(), &parent_stat) != 0 ||
      !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
      !HasSafeAcl(file.Get()) ||
      !IsBoundedExactLifecycleFile(opened, target.identity, target.mode) ||
      !IsBoundedExactLifecycleFile(linked, target.identity, target.mode) ||
      !ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const struct stat before = opened;
  SensitiveBytes bytes(static_cast<size_t>(opened.st_size));
  if (!ReadBoundedFile(env, file.Get(), opened, kMaximumLifecycleWriteBytes, &bytes) ||
      fstat(file.Get(), &opened) != 0 ||
      fstatat(parent.Get(), name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      !HasSafeAcl(file.Get()) ||
      !SameFileState(before, opened) || !SameFileState(before, linked) ||
      !IsBoundedExactLifecycleFile(opened, target.identity, target.mode) ||
      !IsBoundedExactLifecycleFile(linked, target.identity, target.mode) ||
      !ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  napi_value result;
  if (!CreateExactLifecycleWalReadResult(env, bytes, opened, &result)) {
    return nullptr;
  }
  lock->retained_wal_parent_fd = std::move(parent);
  lock->retained_wal_file_fd = std::move(file);
  lock->retained_wal_parent_identity = LifecycleIdentityFromStat(parent_stat);
  lock->retained_wal_identity = LifecycleIdentityFromStat(opened);
  lock->retained_wal_size = static_cast<uint64_t>(opened.st_size);
  lock->retained_wal_mode = opened.st_mode & 0777;
  lock->retained_wal_session_generation = lock->session_generation;
  lock->retained_wal_name = std::move(name);
  lock->retained_wal_digest = Sha256Digest(bytes);
  lock->retained_wal_stat = LifecycleStatSnapshot(opened);
  lock->retained_wal_active = true;
  return result;
}
bool ReadExactLifecycleSnapshotBytes(int fd, SensitiveBytes* bytes) {
  if (fd < 0 || bytes == nullptr) {
    return false;
  }
  size_t offset = 0U;
  while (offset < bytes->Size()) {
    const ssize_t read_count =
        pread(fd, bytes->Data() + offset, bytes->Size() - offset, static_cast<off_t>(offset));
    if (read_count < 0 && errno == EINTR) {
      continue;
    }
    if (read_count <= 0) {
      return false;
    }
    offset += static_cast<size_t>(read_count);
  }
  return true;
}
bool ValidateLifecycleStagedFileReservationSeal(
    const LifecycleStagedFileReservation* reservation, bool require_stat_snapshot,
    std::string* observed_stat) {
  if (reservation == nullptr || !reservation->sealed ||
      reservation->size > kMaximumLifecycleWriteBytes || reservation->file_fd.Get() < 0 ||
      reservation->parent_fd.Get() < 0) {
    return false;
  }
  struct stat parent_stat{};
  struct stat before{};
  struct stat linked{};
  if (fstat(reservation->parent_fd.Get(), &parent_stat) != 0 ||
      fstat(reservation->file_fd.Get(), &before) != 0 ||
      fstatat(reservation->parent_fd.Get(), reservation->name.c_str(), &linked,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !ValidateLifecycleParent(reservation->parent_fd, reservation->parent_identity) ||
      !HasSafeAcl(reservation->file_fd.Get()) ||
      !IsExactLifecycleFile(before, reservation->identity, reservation->mode, reservation->size) ||
      !IsExactLifecycleFile(linked, reservation->identity, reservation->mode, reservation->size) ||
      !SameFileState(before, linked) ||
      (require_stat_snapshot &&
       (LifecycleStatSnapshot(before) != reservation->sealed_stat ||
        LifecycleStatSnapshot(linked) != reservation->sealed_stat))) {
    return false;
  }
  SensitiveBytes bytes(static_cast<size_t>(reservation->size));
  if (!ReadExactLifecycleSnapshotBytes(reservation->file_fd.Get(), &bytes)) {
    return false;
  }
  struct stat after{};
  struct stat linked_after{};
  if (fstat(reservation->file_fd.Get(), &after) != 0 ||
      fstatat(reservation->parent_fd.Get(), reservation->name.c_str(), &linked_after,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !HasSafeAcl(reservation->file_fd.Get()) || !SameFileState(before, after) ||
      !SameFileState(before, linked_after) ||
      !IsExactLifecycleFile(after, reservation->identity, reservation->mode, reservation->size) ||
      !IsExactLifecycleFile(linked_after, reservation->identity, reservation->mode,
                            reservation->size) ||
      Sha256Digest(bytes) != reservation->sealed_digest ||
      (require_stat_snapshot && LifecycleStatSnapshot(after) != reservation->sealed_stat)) {
    return false;
  }
  if (observed_stat != nullptr) {
    *observed_stat = LifecycleStatSnapshot(after);
  }
  return true;
}
bool SealLifecycleStagedFileReservation(LifecycleStagedFileReservation* reservation,
                                        const LifecycleLock* lock) {
  if (reservation == nullptr || reservation->sealed || !ValidateLifecycleLock(lock) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock) ||
      reservation->size > kMaximumLifecycleWriteBytes || reservation->file_fd.Get() < 0) {
    return false;
  }
  struct stat before{};
  struct stat linked{};
  if (fstat(reservation->file_fd.Get(), &before) != 0 ||
      fstatat(reservation->parent_fd.Get(), reservation->name.c_str(), &linked,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !ValidateLifecycleReservationLink(reservation->parent_fd, reservation->parent_identity,
                                        reservation->file_fd.Get(), reservation->name,
                                        reservation->identity, false) ||
      !HasSafeAcl(reservation->file_fd.Get()) ||
      !IsExactLifecycleFile(before, reservation->identity, reservation->mode, reservation->size) ||
      !IsExactLifecycleFile(linked, reservation->identity, reservation->mode, reservation->size) ||
      !SameFileState(before, linked)) {
    return false;
  }
  SensitiveBytes bytes(static_cast<size_t>(reservation->size));
  if (!ReadExactLifecycleSnapshotBytes(reservation->file_fd.Get(), &bytes)) {
    return false;
  }
  struct stat after{};
  struct stat linked_after{};
  if (fstat(reservation->file_fd.Get(), &after) != 0 ||
      fstatat(reservation->parent_fd.Get(), reservation->name.c_str(), &linked_after,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !HasSafeAcl(reservation->file_fd.Get()) || !SameFileState(before, after) ||
      !SameFileState(before, linked_after) ||
      !IsExactLifecycleFile(after, reservation->identity, reservation->mode, reservation->size) ||
      !IsExactLifecycleFile(linked_after, reservation->identity, reservation->mode,
                            reservation->size) ||
      !ValidateLifecycleLock(lock)) {
    return false;
  }
  reservation->sealed_digest = Sha256Digest(bytes);
  reservation->sealed_stat = LifecycleStatSnapshot(after);
  reservation->seal_session_generation = lock->session_generation;
  reservation->sealed = true;
  return ValidateLifecycleStagedFileReservationSeal(reservation, true, nullptr) &&
         ValidateLifecycleStagedFileReservationLock(reservation, lock);
}
bool RefreshLifecycleStagedFileReservationSeal(LifecycleStagedFileReservation* reservation,
                                               const LifecycleLock* lock) {
  std::string observed_stat;
  if (reservation == nullptr || !reservation->sealed || !ValidateLifecycleLock(lock) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock) ||
      !ValidateLifecycleStagedFileReservationSeal(reservation, false, &observed_stat) ||
      !ValidateLifecycleLock(lock)) {
    return false;
  }
  reservation->sealed_stat = std::move(observed_stat);
  reservation->seal_session_generation = lock->session_generation;
  return ValidateLifecycleStagedFileReservationSeal(reservation, true, nullptr) &&
         ValidateLifecycleStagedFileReservationLock(reservation, lock);
}
bool ValidateExactLifecycleContentSnapshot(const LifecycleExactFileRecord& target,
                                           const FileDescriptor& parent, const std::string& name,
                                           const FileDescriptor& file, const LifecycleLock* lock) {
  if (!target.has_content_snapshot || (target.mode & ~static_cast<mode_t>(0777)) != 0 ||
      target.expected_size > kMaximumLifecycleWriteBytes || parent.Get() < 0 ||
      file.Get() < 0) {
    return false;
  }
  struct stat parent_stat{};
  struct stat before{};
  struct stat linked{};
  if (fstat(parent.Get(), &parent_stat) != 0 || fstat(file.Get(), &before) != 0 ||
      fstatat(parent.Get(), name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
      !HasSafeAcl(file.Get()) ||
      !IsExactLifecycleFile(before, target.identity, target.mode, target.expected_size) ||
      !IsExactLifecycleFile(linked, target.identity, target.mode, target.expected_size) ||
      !SameFileState(before, linked) || !ValidateLifecycleLock(lock) ||
      (target.has_stat_snapshot && LifecycleStatSnapshot(before) != target.expected_stat)) {
    return false;
  }
  SensitiveBytes bytes(static_cast<size_t>(target.expected_size));
  if (!ReadExactLifecycleSnapshotBytes(file.Get(), &bytes)) {
    return false;
  }
  struct stat after{};
  struct stat linked_after{};
  return fstat(file.Get(), &after) == 0 &&
         fstatat(parent.Get(), name.c_str(), &linked_after, AT_SYMLINK_NOFOLLOW) == 0 &&
         HasSafeAcl(file.Get()) && SameFileState(before, after) &&
         SameFileState(before, linked_after) &&
         (!target.has_stat_snapshot || LifecycleStatSnapshot(after) == target.expected_stat) &&
         IsExactLifecycleFile(after, target.identity, target.mode, target.expected_size) &&
         IsExactLifecycleFile(linked_after, target.identity, target.mode, target.expected_size) &&
         Sha256Digest(bytes) == target.expected_digest && ValidateLifecycleLock(lock);
}
bool BindRetainedLifecycleQuarantineExactSnapshot(LifecycleQuarantine* quarantine,
                                                   const LifecycleExactFileRecord& target,
                                                   const LifecycleLock* lock) {
  if (quarantine == nullptr || quarantine->kind != LifecycleQuarantineKind::kFile ||
      !target.has_content_snapshot) {
    return false;
  }
  LifecycleExactFileRecord retained{
      .identity = quarantine->quarantine_identity,
      .mode = quarantine->quarantine_mode,
      .has_content_snapshot = true,
      .expected_size = target.expected_size,
      .expected_digest = target.expected_digest,
  };
  if (!ValidateExactLifecycleContentSnapshot(retained, quarantine->parent_fd,
                                             quarantine->quarantine_name, quarantine->entry_fd, lock)) {
    return false;
  }
  struct stat held{};
  struct stat linked{};
  if (fstat(quarantine->entry_fd.Get(), &held) != 0 ||
      fstatat(quarantine->parent_fd.Get(), quarantine->quarantine_name.c_str(), &linked,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameFileState(held, linked)) {
    return false;
  }
  retained.has_stat_snapshot = true;
  retained.expected_stat = LifecycleStatSnapshot(held);
  quarantine->has_content_snapshot = true;
  quarantine->expected_size = retained.expected_size;
  quarantine->expected_digest = retained.expected_digest;
  quarantine->has_stat_snapshot = true;
  quarantine->expected_stat = retained.expected_stat;
  return ValidateExactLifecycleContentSnapshot(retained, quarantine->parent_fd,
                                               quarantine->quarantine_name, quarantine->entry_fd, lock);
}
bool BindSelfLifecycleQuarantineSnapshot(LifecycleQuarantine* quarantine,
                                          const LifecycleLock* lock) {
  if (quarantine == nullptr || quarantine->kind != LifecycleQuarantineKind::kFile ||
      quarantine->entry_fd.Get() < 0 || quarantine->parent_fd.Get() < 0 ||
      !ValidateLifecycleQuarantineLock(quarantine, lock)) {
    return false;
  }
  struct stat held{};
  struct stat linked{};
  if (fstat(quarantine->entry_fd.Get(), &held) != 0 ||
      fstatat(quarantine->parent_fd.Get(), quarantine->quarantine_name.c_str(), &linked,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameFileState(held, linked) || !SameIdentity(held, quarantine->quarantine_identity) ||
      held.st_size < 0 ||
      static_cast<uint64_t>(held.st_size) > kMaximumLifecycleWriteBytes) {
    return false;
  }
  SensitiveBytes bytes(static_cast<size_t>(held.st_size));
  if (!ReadExactLifecycleSnapshotBytes(quarantine->entry_fd.Get(), &bytes)) {
    return false;
  }
  LifecycleExactFileRecord retained{
      .identity = quarantine->quarantine_identity,
      .mode = quarantine->quarantine_mode,
      .has_content_snapshot = true,
      .expected_size = static_cast<uint64_t>(held.st_size),
      .expected_digest = Sha256Digest(bytes),
      .has_stat_snapshot = true,
      .expected_stat = LifecycleStatSnapshot(held),
  };
  quarantine->has_content_snapshot = true;
  quarantine->expected_size = retained.expected_size;
  quarantine->expected_digest = retained.expected_digest;
  quarantine->has_stat_snapshot = true;
  quarantine->expected_stat = retained.expected_stat;
  return ValidateExactLifecycleContentSnapshot(retained, quarantine->parent_fd,
                                               quarantine->quarantine_name, quarantine->entry_fd,
                                               lock);
}
bool ValidateRetainedLifecycleQuarantineExactSnapshot(const LifecycleQuarantine* quarantine,
                                                       const LifecycleLock* lock) {
  if (quarantine == nullptr || !quarantine->has_content_snapshot) {
    return quarantine != nullptr;
  }
  if (quarantine->kind != LifecycleQuarantineKind::kFile || !quarantine->has_stat_snapshot ||
      quarantine->expected_stat.empty()) {
    return false;
  }
  const LifecycleExactFileRecord target{
      .identity = quarantine->quarantine_identity,
      .mode = quarantine->quarantine_mode,
      .has_content_snapshot = true,
      .expected_size = quarantine->expected_size,
      .expected_digest = quarantine->expected_digest,
      .has_stat_snapshot = true,
      .expected_stat = quarantine->expected_stat,
  };
  return ValidateExactLifecycleContentSnapshot(target, quarantine->parent_fd,
                                               quarantine->quarantine_name, quarantine->entry_fd, lock);
}
bool BindPostExchangeLifecycleExactSnapshot(LifecycleExactFileRecord* target,
                                            const FileDescriptor& parent, const std::string& name,
                                            const FileDescriptor& file,
                                            const LifecycleLock* lock) {
  if (target == nullptr || !target->has_content_snapshot) {
    return false;
  }
  target->has_stat_snapshot = false;
  target->expected_stat.clear();
  if (!ValidateExactLifecycleContentSnapshot(*target, parent, name, file, lock)) {
    return false;
  }
  struct stat held{};
  struct stat linked{};
  if (fstat(file.Get(), &held) != 0 ||
      fstatat(parent.Get(), name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      !SameFileState(held, linked)) {
    return false;
  }
  target->has_stat_snapshot = true;
  target->expected_stat = LifecycleStatSnapshot(held);
  return ValidateExactLifecycleContentSnapshot(*target, parent, name, file, lock);
}
bool RefreshRetainedLifecycleQuarantineExactSnapshotAtName(LifecycleQuarantine* quarantine,
                                                           const std::string& name,
                                                           const LifecycleLock* lock) {
  if (quarantine == nullptr || !quarantine->has_content_snapshot ||
      !quarantine->has_stat_snapshot || quarantine->expected_stat.empty()) {
    return quarantine != nullptr && !quarantine->has_content_snapshot;
  }
  LifecycleExactFileRecord target{
      .identity = quarantine->quarantine_identity,
      .mode = quarantine->quarantine_mode,
      .has_content_snapshot = true,
      .expected_size = quarantine->expected_size,
      .expected_digest = quarantine->expected_digest,
      .has_stat_snapshot = true,
      .expected_stat = quarantine->expected_stat,
  };
  if (!BindPostExchangeLifecycleExactSnapshot(&target, quarantine->parent_fd, name,
                                              quarantine->entry_fd, lock)) {
    return false;
  }
  quarantine->expected_stat = std::move(target.expected_stat);
  return true;
}
bool ValidateExactLifecycleWalSnapshot(const LifecycleExactFileRecord& target,
                                       const FileDescriptor& parent, const std::string& name,
                                       const FileDescriptor& file, const LifecycleLock* lock) {
  return target.mode == 0600 && target.has_stat_snapshot &&
         ValidateExactLifecycleContentSnapshot(target, parent, name, file, lock);
}

bool ValidateRetainedLifecycleWal(const LifecycleLock* lock) {
  if (lock == nullptr || !lock->retained_wal_active ||
      lock->retained_wal_session_generation != lock->session_generation) {
    return false;
  }
  LifecycleExactFileRecord target{
      .identity = lock->retained_wal_identity,
      .mode = lock->retained_wal_mode,
      .has_content_snapshot = true,
      .expected_size = lock->retained_wal_size,
      .expected_digest = lock->retained_wal_digest,
      .has_stat_snapshot = true,
      .expected_stat = lock->retained_wal_stat,
  };
  return ValidateExactLifecycleWalSnapshot(target, lock->retained_wal_parent_fd,
                                           lock->retained_wal_name,
                                           lock->retained_wal_file_fd, lock);
}
bool MatchesRetainedLifecycleWalSnapshot(const LifecycleExactFileRecord& target,
                                         const LifecycleLock* lock) {
  return lock != nullptr && lock->retained_wal_active &&
         lock->retained_wal_session_generation == lock->session_generation &&
         target.mode == lock->retained_wal_mode && target.has_content_snapshot &&
         target.has_stat_snapshot && SameIdentity(target.identity, lock->retained_wal_identity) &&
         target.expected_size == lock->retained_wal_size &&
         target.expected_digest == lock->retained_wal_digest &&
         target.expected_stat == lock->retained_wal_stat;
}
bool ValidateRetainedLifecycleWalTarget(const LifecycleExactFileRecord& target,
                                        const FileDescriptor& parent, const std::string& name,
                                        const LifecycleLock* lock) {
  return MatchesRetainedLifecycleWalSnapshot(target, lock) && parent.Get() >= 0 &&
         SameLifecycleDirectory(parent.Get(), lock->retained_wal_parent_fd.Get()) &&
         name == lock->retained_wal_name && ValidateRetainedLifecycleWal(lock);
}

bool ParseLifecycleCreationIntentOptions(napi_env env, napi_value options, std::string* path,
                                         std::string* marker_path, LifecycleCreationIntentKind* kind,
                                         LifecycleLock** lock) {
  napi_value path_value;
  napi_value marker_path_value;
  napi_value kind_value;
  std::string parsed_kind;
  if (!GetRequiredProperty(env, options, "path", &path_value) ||
      !GetRequiredProperty(env, options, "markerPath", &marker_path_value) ||
      !GetRequiredProperty(env, options, "kind", &kind_value) ||
      !ParseLifecyclePath(env, path_value, path) ||
      !ParseLifecyclePath(env, marker_path_value, marker_path) ||
      !GetString(env, kind_value, &parsed_kind, 16U) || !ParseLifecycleLock(env, options, lock)) {
    return false;
  }
  if (parsed_kind == "credential") {
    *kind = LifecycleCreationIntentKind::kCredential;
    return true;
  }
  if (parsed_kind == "file") {
    *kind = LifecycleCreationIntentKind::kFile;
    return true;
  }
  if (parsed_kind == "directory") {
    *kind = LifecycleCreationIntentKind::kDirectory;
    return true;
  }
  ThrowLifecycleDenied(env);
  return false;
}
napi_value PrepareLifecycleCreationIntent(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value parent_directory_reservation_value;
  bool has_parent_directory_reservation = false;
  LifecycleStagedDirectoryReservation* parent_directory_reservation = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !IsNapiStatusOk(napi_has_named_property(env, options, "parentDirectoryReservation",
                                              &has_parent_directory_reservation)) ||
      (has_parent_directory_reservation &&
       (!GetRequiredProperty(env, options, "parentDirectoryReservation",
                             &parent_directory_reservation_value) ||
        !RequireLifecycleStagedDirectoryReservation(env, parent_directory_reservation_value,
                                                    &parent_directory_reservation)))) {
    return nullptr;
  }

  std::string path;
  std::string marker_path;
  LifecycleCreationIntentKind kind;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleCreationIntentOptions(env, options, &path, &marker_path, &kind, &lock)) {
    return nullptr;
  }
  FileDescriptor parent;
  FileDescriptor marker_parent;
  std::string stage_name;
  std::string marker_name;
  struct stat parent_stat{};
  if (parent_directory_reservation != nullptr) {
    const size_t stage_separator = path.rfind('/');
    const size_t marker_separator = marker_path.rfind('/');
    if (stage_separator == std::string::npos || marker_separator == std::string::npos ||
        stage_separator + 1U >= path.size() || marker_separator + 1U >= marker_path.size() ||
        path.compare(0U, stage_separator, marker_path, 0U, marker_separator) != 0 ||
        !ValidateLifecycleStagedDirectoryReservation(parent_directory_reservation) ||
        !ValidateLifecycleStagedDirectoryReservationLock(parent_directory_reservation, lock)) {
      ThrowLifecycleDenied(env);
      return nullptr;
    }
    stage_name = path.substr(stage_separator + 1U);
    marker_name = marker_path.substr(marker_separator + 1U);
    parent.Reset(dup(parent_directory_reservation->directory_fd.Get()));
    if (parent.Get() < 0 || stage_name == marker_name || fstat(parent.Get(), &parent_stat) != 0 ||
        !SameIdentity(LifecycleIdentityFromStat(parent_stat), parent_directory_reservation->identity) ||
        !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
        !ValidateLifecycleStagedDirectoryReservation(parent_directory_reservation) ||
        !ValidateLifecycleStagedDirectoryReservationLock(parent_directory_reservation, lock)) {
      ThrowLifecycleDenied(env);
      return nullptr;
    }
  } else if (!OpenLifecycleParent(env, path, &parent, &stage_name) ||
             !OpenLifecycleParent(env, marker_path, &marker_parent, &marker_name) ||
             stage_name == marker_name || !SameLifecycleDirectory(parent.Get(), marker_parent.Get()) ||
             fstat(parent.Get(), &parent_stat) != 0 ||
             !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
             !ValidateLifecycleLock(lock)) {
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_lifecycle_reservations, kMaximumLifecycleReservations)) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  const std::string validation_token =
      LifecycleCreationIntentValidationTokenFromMarkerName(marker_name);
  std::string private_marker_name;
  if (validation_token.empty() ||
      !LifecycleCreationIntentPrivateMarkerName(marker_name, &private_marker_name)) {
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  auto* intent = new (std::nothrow) LifecycleCreationIntent{
      .parent_fd = std::move(parent),
      .marker_fd = FileDescriptor(),
      .parent_identity = LifecycleIdentityFromStat(parent_stat),
      .lock_identity = lock->identity,
      .lock_session_generation = lock->session_generation,
      .stage_name = std::move(stage_name),
      .marker_name = std::move(marker_name),
      .validation_token = validation_token,
      .kind = kind,
      .slot_charged = true,
  };
  if (intent == nullptr) {
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  napi_value intent_value;
  if (!IsNapiStatusOk(napi_create_object(env, &intent_value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, intent_value, &kLifecycleCreationIntentTypeTag)) ||
      !IsNapiStatusOk(
          napi_wrap(env, intent_value, intent, FinalizeLifecycleCreationIntent, nullptr, nullptr))) {
    CloseLifecycleCreationIntent(intent);
    delete intent;
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  napi_value result;
  napi_value indeterminate_state;
  napi_value completed_state;
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(
          napi_create_string_utf8(env, "indeterminate", NAPI_AUTO_LENGTH, &indeterminate_state)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, "completed", NAPI_AUTO_LENGTH, &completed_state)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", indeterminate_state)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "intent", intent_value))) {
    CloseLifecycleCreationIntent(intent);
    ThrowLifecycleFailure(env);
    return nullptr;
  }

  FileDescriptor marker;
  const mode_t marker_mode = kind == LifecycleCreationIntentKind::kDirectory ? 0700 : 0600;
  if (kind == LifecycleCreationIntentKind::kDirectory) {
    if (mkdirat(intent->parent_fd.Get(), private_marker_name.c_str(), marker_mode) != 0) {
      CloseLifecycleCreationIntent(intent);
      ThrowLifecycleDenied(env);
      return nullptr;
    }
    marker.Reset(openat(intent->parent_fd.Get(), private_marker_name.c_str(),
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  } else {
    marker.Reset(openat(intent->parent_fd.Get(), private_marker_name.c_str(),
                        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, marker_mode));
  }
  intent->marker_fd = std::move(marker);
  struct stat marker_stat{};
  if (intent->marker_fd.Get() < 0 || fstat(intent->marker_fd.Get(), &marker_stat) != 0 ||
      (kind == LifecycleCreationIntentKind::kDirectory ? !S_ISDIR(marker_stat.st_mode)
                                                        : !S_ISREG(marker_stat.st_mode))) {
    return result;
  }
  intent->marker_identity = LifecycleIdentityFromStat(marker_stat);
  const bool initialized = fchmod(intent->marker_fd.Get(), marker_mode) == 0 &&
                           ClearInheritedAcl(intent->marker_fd.Get()) &&
                           fsync(intent->marker_fd.Get()) == 0 &&
                           SetLifecycleCreationIntentValidationToken(intent->marker_fd.Get(),
                                                                     intent->validation_token) &&
                           fsync(intent->marker_fd.Get()) == 0 &&
                           MatchesLifecycleCreationIntentValidationToken(intent->marker_fd.Get(),
                                                                         intent->validation_token) &&
                           ValidateLifecycleCreationIntentMarker(
                               intent->parent_fd, intent->marker_fd, private_marker_name,
                               intent->marker_identity, intent->kind) &&
                           fsync(intent->parent_fd.Get()) == 0 &&
                           ValidateLifecycleCreationIntentMarker(
                               intent->parent_fd, intent->marker_fd, private_marker_name,
                               intent->marker_identity, intent->kind);
  const bool completed =
      initialized &&
      RenameLifecycleNoReplace(intent->parent_fd.Get(), private_marker_name, intent->marker_name) ==
          LifecycleNoReplaceResult::kCompleted &&
      ValidateLifecycleCreationIntent(intent, lock) && fsync(intent->parent_fd.Get()) == 0 &&
      ValidateLifecycleCreationIntent(intent, lock);
  intent->prepared = completed;
  if (completed &&
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", completed_state))) {
    intent->prepared = false;
  }
  return result;
}
bool ParseRecoverLifecycleCreationIntentOptions(napi_env env, napi_callback_info info,
                                               std::string* stage_path, std::string* marker_path,
                                               LifecycleCreationIntentKind* kind, mode_t* mode,
                                               LifecycleLock** lock) {
  napi_value options;
  napi_value stage_value;
  napi_value marker_value;
  napi_value kind_value;
  napi_value mode_value;
  std::string parsed_kind;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "stagePath", &stage_value) ||
      !GetRequiredProperty(env, options, "markerPath", &marker_value) ||
      !GetRequiredProperty(env, options, "kind", &kind_value) ||
      !GetRequiredProperty(env, options, "mode", &mode_value) ||
      !ParseLifecyclePath(env, stage_value, stage_path) ||
      !ParseLifecyclePath(env, marker_value, marker_path) ||
      !GetString(env, kind_value, &parsed_kind, 16U) ||
      !ParseLifecycleMode(env, mode_value, mode) || !ParseLifecycleLock(env, options, lock)) {
    return false;
  }
  if (parsed_kind == "credential" && *mode == 0600) {
    *kind = LifecycleCreationIntentKind::kCredential;
    return true;
  }
  if (parsed_kind == "file") {
    *kind = LifecycleCreationIntentKind::kFile;
    return true;
  }
  if (parsed_kind == "directory") {
    *kind = LifecycleCreationIntentKind::kDirectory;
    return true;
  }
  ThrowLifecycleDenied(env);
  return false;
}
bool ValidateRecoverableLifecycleCreationIntentEntry(
    int parent_fd, const std::string& name, LifecycleCreationIntentKind kind, mode_t mode,
    const std::string& validation_token, Identity* identity) {
  FileDescriptor entry(kind == LifecycleCreationIntentKind::kDirectory
                           ? OpenDirectoryAt(parent_fd, name)
                           : openat(parent_fd, name.c_str(),
                                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  struct stat stat{};
  if (entry.Get() < 0 || fstat(entry.Get(), &stat) != 0 || !HasSafeAcl(entry.Get()) ||
      !MatchesLifecycleCreationIntentValidationToken(entry.Get(), validation_token)) {
    return false;
  }
  *identity = LifecycleIdentityFromStat(stat);
  if (kind == LifecycleCreationIntentKind::kDirectory) {
    return IsExactLifecycleDirectory(stat, *identity, mode) && IsEmptyLifecycleDirectory(entry.Get());
  }
  if (kind == LifecycleCreationIntentKind::kFile && stat.st_size >= 0) {
    return IsExactLifecycleFile(
        stat, *identity, mode, static_cast<uint64_t>(stat.st_size));
  }
  return IsExactLifecycleFile(stat, *identity, mode, 0U);
}
bool OpenRecoverablePrivateLifecycleCreationIntentEntry(
    int parent_fd, const std::string& name, LifecycleCreationIntentKind kind, mode_t mode,
    const std::string& validation_token, FileDescriptor* output, Identity* identity) {
  if (output == nullptr || identity == nullptr) {
    return false;
  }
  FileDescriptor entry(kind == LifecycleCreationIntentKind::kDirectory
                           ? OpenDirectoryAt(parent_fd, name)
                           : openat(parent_fd, name.c_str(),
                                    O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  struct stat stat{};
  const LifecycleCreationIntentValidationTokenState token_state =
      entry.Get() < 0
          ? LifecycleCreationIntentValidationTokenState::kMismatched
          : LifecycleCreationIntentValidationTokenStateForFd(entry.Get(), validation_token);
  if (entry.Get() < 0 || fstat(entry.Get(), &stat) != 0 ||
      (token_state != LifecycleCreationIntentValidationTokenState::kMatches &&
       token_state != LifecycleCreationIntentValidationTokenState::kAbsent)) {
    return false;
  }
  *identity = LifecycleIdentityFromStat(stat);
  const mode_t actual_mode = static_cast<mode_t>(stat.st_mode & 07777);
  const bool exact_shape =
      kind == LifecycleCreationIntentKind::kDirectory
          ? (S_ISDIR(stat.st_mode) && stat.st_nlink >= 2 && IsLifecycleOwner(stat) &&
             actual_mode == mode && IsEmptyLifecycleDirectory(entry.Get()))
          : (S_ISREG(stat.st_mode) && stat.st_nlink == 1 && IsLifecycleOwner(stat) &&
             actual_mode == mode && stat.st_size == 0);
  const bool uninitialized_private_shape =
      kind == LifecycleCreationIntentKind::kDirectory
          ? (S_ISDIR(stat.st_mode) && stat.st_nlink >= 2 && IsLifecycleOwner(stat) &&
             (actual_mode & ~mode) == 0 && IsEmptyLifecycleDirectory(entry.Get()))
          : (S_ISREG(stat.st_mode) && stat.st_nlink == 1 && IsLifecycleOwner(stat) &&
             (actual_mode & ~mode) == 0 && stat.st_size == 0);
  if (!((token_state == LifecycleCreationIntentValidationTokenState::kMatches && exact_shape &&
         HasSafeAcl(entry.Get())) ||
        (token_state == LifecycleCreationIntentValidationTokenState::kAbsent &&
         uninitialized_private_shape))) {
    return false;
  }
  *output = std::move(entry);
  return true;
}

bool LifecycleCreationIntentMarkerPrefix(const std::string& marker_name,
                                         LifecycleCreationIntentKind kind, mode_t mode,
                                         std::string* prefix) {
  constexpr char kMarkerLead[] = ".scg-intent-";
  constexpr char kMarkerSuffix[] = ".marker";
  constexpr size_t kStageTokenBytes = 16U;
  constexpr size_t kIntentTokenBytes = 32U;
  char encoded_mode[4] = {};
  if (std::snprintf(encoded_mode, sizeof(encoded_mode), "%03o",
                    static_cast<unsigned int>(mode)) != 3) {
    return false;
  }
  const char* const kind_name =
      kind == LifecycleCreationIntentKind::kCredential
          ? "credential"
          : (kind == LifecycleCreationIntentKind::kFile ? "file" : "directory");
  const size_t lead_size = sizeof(kMarkerLead) - 1U;
  const size_t kind_size = std::strlen(kind_name);
  const size_t stage_token_offset = lead_size;
  const size_t kind_offset = stage_token_offset + kStageTokenBytes + 1U;
  const size_t mode_offset = kind_offset + kind_size + 1U;
  const size_t token_offset = mode_offset + 3U + 1U;
  const size_t expected_size =
      token_offset + kIntentTokenBytes + (sizeof(kMarkerSuffix) - 1U);
  if (marker_name.size() != expected_size ||
      marker_name.compare(0U, lead_size, kMarkerLead) != 0 ||
      !IsLowerHexLifecycleToken(marker_name, stage_token_offset, kStageTokenBytes) ||
      marker_name[kind_offset - 1U] != '-' ||
      marker_name.compare(kind_offset, kind_size, kind_name) != 0 ||
      marker_name[mode_offset - 1U] != '-' ||
      marker_name.compare(mode_offset, 3U, encoded_mode) != 0 ||
      marker_name[token_offset - 1U] != '-' ||
      !IsLowerHexLifecycleToken(marker_name, token_offset, kIntentTokenBytes) ||
      marker_name.compare(token_offset + kIntentTokenBytes, sizeof(kMarkerSuffix) - 1U,
                          kMarkerSuffix) != 0) {
    return false;
  }
  *prefix = marker_name.substr(0U, kind_offset);
  return true;
}

bool HasCompetingLifecycleCreationIntentMarker(int parent_fd, const std::string& marker_name,
                                               const std::string& private_marker_name,
                                               LifecycleCreationIntentKind kind, mode_t mode) {
  std::string prefix;
  if (!LifecycleCreationIntentMarkerPrefix(marker_name, kind, mode, &prefix)) {
    return true;
  }
  const int duplicated_fd = OpenDirectoryAt(parent_fd, ".");
  if (duplicated_fd < 0) {
    return true;
  }
  DIR* directory = fdopendir(duplicated_fd);
  if (directory == nullptr) {
    (void)close(duplicated_fd);
    return true;
  }
  bool competing = false;
  for (;;) {
    errno = 0;
    struct dirent* entry = readdir(directory);
    if (entry == nullptr) {
      competing = competing || errno != 0;
      break;
    }
    if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    const std::string candidate(entry->d_name);
    if (candidate != marker_name && candidate != private_marker_name &&
        candidate.size() > prefix.size() && candidate.compare(0U, prefix.size(), prefix) == 0) {
      competing = true;
      break;
    }
  }
  return closedir(directory) != 0 || competing;
}
napi_value RecoverLifecycleCreationIntent(napi_env env, napi_callback_info info) {
  std::string stage_path;
  std::string marker_path;
  LifecycleCreationIntentKind kind;
  mode_t mode = 0;
  LifecycleLock* lock = nullptr;
  if (!ParseRecoverLifecycleCreationIntentOptions(env, info, &stage_path, &marker_path, &kind, &mode,
                                                  &lock)) {
    return nullptr;
  }
  FileDescriptor parent;
  FileDescriptor marker_parent;
  std::string stage_name;
  std::string marker_name;
  struct stat parent_stat{};
  if (!OpenLifecycleParent(env, stage_path, &parent, &stage_name) ||
      !OpenLifecycleParent(env, marker_path, &marker_parent, &marker_name) ||
      stage_name == marker_name || !SameLifecycleDirectory(parent.Get(), marker_parent.Get()) ||
      fstat(parent.Get(), &parent_stat) != 0 ||
      !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
      !ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const std::string validation_token =
      LifecycleCreationIntentValidationTokenFromMarkerName(marker_name);
  std::string private_marker_name;
  if (validation_token.empty() ||
      !LifecycleCreationIntentPrivateMarkerName(marker_name, &private_marker_name) ||
      HasCompetingLifecycleCreationIntentMarker(parent.Get(), marker_name, private_marker_name, kind,
                                                mode)) {
    return LifecycleResult(env, "indeterminate");
  }

  struct stat stage_stat{};
  struct stat marker_stat{};
  struct stat private_marker_stat{};
  const bool stage_exists =
      fstatat(parent.Get(), stage_name.c_str(), &stage_stat, AT_SYMLINK_NOFOLLOW) == 0;
  const int stage_error = errno;
  const bool marker_exists =
      fstatat(parent.Get(), marker_name.c_str(), &marker_stat, AT_SYMLINK_NOFOLLOW) == 0;
  const int marker_error = errno;
  const bool private_marker_exists =
      fstatat(parent.Get(), private_marker_name.c_str(), &private_marker_stat, AT_SYMLINK_NOFOLLOW) ==
      0;
  const int private_marker_error = errno;
  const uint32_t existing_entries = static_cast<uint32_t>(stage_exists) +
                                    static_cast<uint32_t>(marker_exists) +
                                    static_cast<uint32_t>(private_marker_exists);
  if ((!stage_exists && stage_error != ENOENT) || (!marker_exists && marker_error != ENOENT) ||
      (!private_marker_exists && private_marker_error != ENOENT) || existing_entries > 1U) {
    return LifecycleResult(env, "indeterminate");
  }
  if (existing_entries == 0U) {
    return LifecycleLockedResult(env, lock);
  }
  if (private_marker_exists) {
    const mode_t private_marker_mode =
        kind == LifecycleCreationIntentKind::kDirectory ? 0700 : 0600;
    FileDescriptor private_marker;
    Identity private_marker_identity{};
    if (!OpenRecoverablePrivateLifecycleCreationIntentEntry(
            parent.Get(), private_marker_name, kind, private_marker_mode, validation_token,
            &private_marker, &private_marker_identity) ||
        fchmod(private_marker.Get(), private_marker_mode) != 0 ||
        !ClearInheritedAcl(private_marker.Get()) || fsync(private_marker.Get()) != 0 ||
        LifecycleCreationIntentValidationTokenStateForFd(private_marker.Get(), validation_token) ==
            LifecycleCreationIntentValidationTokenState::kMismatched ||
        !ValidateLifecycleCreationIntentMarker(
            parent, private_marker, private_marker_name, private_marker_identity, kind) ||
        !DiscardLifecycleReservationLink(
            parent, LifecycleIdentityFromStat(parent_stat), private_marker.Get(), private_marker_name,
            private_marker_identity, kind == LifecycleCreationIntentKind::kDirectory, lock)) {
      return LifecycleResult(env, "indeterminate");
    }
    return LifecycleLockedResult(env, lock);
  }

  const bool remove_stage = stage_exists;
  const std::string& existing_name = remove_stage ? stage_name : marker_name;
  const std::string& quarantine_name = remove_stage ? marker_name : stage_name;
  const mode_t expected_mode =
      remove_stage ? mode : (kind == LifecycleCreationIntentKind::kDirectory ? 0700 : 0600);
  Identity identity{};
  if (!ValidateRecoverableLifecycleCreationIntentEntry(parent.Get(), existing_name, kind, expected_mode,
                                                        validation_token, &identity)) {
    return LifecycleResult(env, "indeterminate");
  }
  FileDescriptor quarantine_parent(dup(parent.Get()));
  if (quarantine_parent.Get() < 0) {
    return LifecycleResult(env, "indeterminate");
  }
  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (!CreateLifecycleQuarantine(
          env, lock, &quarantine_parent, existing_name, quarantine_name, identity, identity,
          expected_mode, expected_mode,
          kind == LifecycleCreationIntentKind::kDirectory ? LifecycleQuarantineKind::kDirectory
                                                           : LifecycleQuarantineKind::kFile,
          LifecycleQuarantineOperation::kMove, &quarantine, &quarantine_value)) {
    return nullptr;
  }
  const LifecycleQuarantineKind quarantine_kind =
      kind == LifecycleCreationIntentKind::kDirectory ? LifecycleQuarantineKind::kDirectory
                                                      : LifecycleQuarantineKind::kFile;
  const LifecycleExactMoveResult moved = MoveExactLifecycleEntryToQuarantine(
      quarantine->parent_fd.Get(), existing_name, quarantine_name, identity, expected_mode,
      quarantine_kind, lock);
  if (moved == LifecycleExactMoveResult::kCompleted) {
    quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
    if (quarantine_kind == LifecycleQuarantineKind::kFile &&
        !BindSelfLifecycleQuarantineSnapshot(quarantine, lock)) {
      return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
    }
    return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &identity, quarantine_value);
  }
  if (moved == LifecycleExactMoveResult::kRestoredForeign) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
}
napi_value LifecycleCreationIntentRequired(napi_env env, napi_callback_info) {
  ThrowLifecycleDenied(env);
  return nullptr;
}

bool ParseLifecycleReserveFromIntentOptions(napi_env env, napi_callback_info info, mode_t* mode,
                                            LifecycleCreationIntent** intent,
                                            LifecycleLock** lock) {
  napi_value options;
  napi_value mode_value;
  napi_value intent_value;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, "mode", &mode_value) &&
         GetRequiredProperty(env, options, "intent", &intent_value) &&
         ParseLifecycleMode(env, mode_value, mode) &&
         RequireLifecycleCreationIntent(env, intent_value, intent) &&
         ParseLifecycleLock(env, options, lock);
}
bool IsApprovedLifecycleStageFileMode(mode_t mode) {
  return (mode & ~static_cast<mode_t>(0777)) == 0;
}
napi_value ReserveCredentialFromIntent(napi_env env, napi_callback_info info) {
  mode_t mode = 0;
  LifecycleCreationIntent* intent = nullptr;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleReserveFromIntentOptions(env, info, &mode, &intent, &lock)) {
    return nullptr;
  }
  if (
    !IsApprovedLifecycleStageFileMode(mode) ||
    (intent->kind != LifecycleCreationIntentKind::kCredential &&
     intent->kind != LifecycleCreationIntentKind::kFile) ||
    (intent->kind == LifecycleCreationIntentKind::kCredential && mode != 0600) ||
    !RefreshLifecycleCreationIntentAuthority(intent, lock)
  ) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  const bool intent_prepared = intent->prepared && ValidateLifecycleCreationIntent(intent, lock);
  const Identity identity = intent->marker_identity;
  auto* reservation = new (std::nothrow) LifecycleStagedFileReservation{
      .parent_fd = FileDescriptor(),
      .file_fd = FileDescriptor(),
      .parent_identity = intent->parent_identity,
      .identity = identity,
      .lock_identity = intent->lock_identity,
      .lock_session_generation = intent->lock_session_generation,
      .name = intent->marker_name,
      .mode = mode,
  };
  if (reservation == nullptr) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, false, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    ThrowLifecycleFailure(env);
    return nullptr;
  }

  napi_value reservation_value;
  if (!IsNapiStatusOk(napi_create_object(env, &reservation_value)) ||
      !IsNapiStatusOk(
          napi_type_tag_object(env, reservation_value, &kLifecycleStagedFileReservationTypeTag)) ||
      !IsNapiStatusOk(napi_wrap(env, reservation_value, reservation,
                                 FinalizeLifecycleStagedFileReservation, nullptr, nullptr))) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, false, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    delete reservation;
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  napi_value result;
  napi_value completed_state;
  if (!CreateLifecycleMutationResult(env, "indeterminate", &identity, &result)) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, false, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    return nullptr;
  }
  if (!IsNapiStatusOk(napi_create_string_utf8(env, "completed", NAPI_AUTO_LENGTH, &completed_state)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "reservation", reservation_value))) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, false, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  reservation->parent_fd = std::move(intent->parent_fd);
  reservation->file_fd = std::move(intent->marker_fd);
  reservation->slot_charged = true;
  intent->consumed = true;
  intent->slot_charged = false;
  CloseLifecycleCreationIntent(intent);

  const bool renamed =
      intent_prepared &&
      ValidateLifecycleReservationLink(reservation->parent_fd, reservation->parent_identity,
                                       reservation->file_fd.Get(), reservation->name,
                                       reservation->identity, false) &&
      ValidateLifecycleStagedFileReservationLock(reservation, lock) &&
      RenameLifecycleNoReplace(reservation->parent_fd.Get(), reservation->name, intent->stage_name) ==
          LifecycleNoReplaceResult::kCompleted;
  if (renamed) {
    reservation->name = intent->stage_name;
    reservation->link_state = LifecycleReservationLinkState::kStage;
  }
  bool completed = renamed && fchmod(reservation->file_fd.Get(), mode) == 0 &&
                   ClearInheritedAcl(reservation->file_fd.Get()) &&
                   fsync(reservation->file_fd.Get()) == 0 &&
                   ValidateLifecycleStagedFileReservation(reservation) &&
                   fsync(reservation->parent_fd.Get()) == 0 &&
                   ValidateLifecycleStagedFileReservationLock(reservation, lock);
  if (completed &&
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", completed_state))) {
    completed = false;
  }
  if (!completed) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
  }
  return result;
}
bool ParseReserveLifecycleStagedFileOptions(napi_env env, napi_callback_info info, std::string* path,
                                            mode_t* mode, LifecycleLock** lock) {
  napi_value options;
  napi_value path_value;
  napi_value mode_value;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, "path", &path_value) &&
         GetRequiredProperty(env, options, "mode", &mode_value) &&
         ParseLifecyclePath(env, path_value, path) && ParseLifecycleMode(env, mode_value, mode) &&
         ParseLifecycleLock(env, options, lock);
}

napi_value ReserveLifecycleStagedFile(napi_env env, napi_callback_info info) {
  std::string path;
  std::string name;
  mode_t mode = 0;
  LifecycleLock* lock = nullptr;
  FileDescriptor parent;
  struct stat parent_stat{};
  if (!ParseReserveLifecycleStagedFileOptions(env, info, &path, &mode, &lock) ||
      !IsApprovedLifecycleStageFileMode(mode) ||
      !OpenLifecycleParent(env, path, &parent, &name) ||
      fstat(parent.Get(), &parent_stat) != 0 ||
      !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
      !ValidateLifecycleLock(lock)) {
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_lifecycle_reservations, kMaximumLifecycleReservations)) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  FileDescriptor file(
      openat(parent.Get(), name.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode));
  struct stat file_stat{};
  if (file.Get() < 0 || fstat(file.Get(), &file_stat) != 0 || !S_ISREG(file_stat.st_mode) ||
      file_stat.st_nlink != 1 || !IsLifecycleOwner(file_stat)) {
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  const Identity identity = LifecycleIdentityFromStat(file_stat);
  if (fchmod(file.Get(), mode) != 0 || !ClearInheritedAcl(file.Get()) || fsync(file.Get()) != 0 ||
      !ValidateBoundedLifecycleFileAt(parent.Get(), name, identity, mode) ||
      fsync(parent.Get()) != 0 || !ValidateLifecycleLock(lock)) {
    (void)DiscardLifecycleReservationLink(parent, LifecycleIdentityFromStat(parent_stat), file.Get(),
                                          name, identity, false, lock);
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  auto* reservation = new (std::nothrow) LifecycleStagedFileReservation{
      .parent_fd = std::move(parent),
      .file_fd = std::move(file),
      .parent_identity = LifecycleIdentityFromStat(parent_stat),
      .identity = identity,
      .lock_identity = lock->identity,
      .lock_session_generation = lock->session_generation,
      .name = name,
      .mode = mode,
      .link_state = LifecycleReservationLinkState::kStage,
      .slot_charged = true,
  };
  if (reservation == nullptr) {
    (void)DiscardLifecycleReservationLink(parent, LifecycleIdentityFromStat(parent_stat), file.Get(),
                                          name, identity, false, lock);
    ReleaseAuthoritySlot(&active_lifecycle_reservations);
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  napi_value reservation_value;
  if (!IsNapiStatusOk(napi_create_object(env, &reservation_value)) ||
      !IsNapiStatusOk(
          napi_type_tag_object(env, reservation_value, &kLifecycleStagedFileReservationTypeTag)) ||
      !IsNapiStatusOk(napi_wrap(env, reservation_value, reservation,
                                 FinalizeLifecycleStagedFileReservation, nullptr, nullptr))) {
    if (DiscardLifecycleReservationLink(reservation->parent_fd, reservation->parent_identity,
                                        reservation->file_fd.Get(), reservation->name,
                                        reservation->identity, false, lock)) {
      reservation->state = LifecycleStagedFileReservationState::kDiscarded;
    }
    CloseLifecycleStagedFileReservation(reservation);
    delete reservation;
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  napi_value result;
  napi_value completed_state;
  if (!CreateLifecycleMutationResult(env, "indeterminate", &identity, &result) ||
      !IsNapiStatusOk(
          napi_create_string_utf8(env, "completed", NAPI_AUTO_LENGTH, &completed_state)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "reservation", reservation_value))) {
    if (DiscardLifecycleReservationLink(reservation->parent_fd, reservation->parent_identity,
                                        reservation->file_fd.Get(), reservation->name,
                                        reservation->identity, false, lock)) {
      reservation->state = LifecycleStagedFileReservationState::kDiscarded;
    } else {
      reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    }
    CloseLifecycleStagedFileReservation(reservation);
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  bool completed = fchmod(reservation->file_fd.Get(), mode) == 0 &&
                   ClearInheritedAcl(reservation->file_fd.Get()) &&
                   fsync(reservation->file_fd.Get()) == 0 &&
                   ValidateLifecycleStagedFileReservation(reservation) &&
                   fsync(reservation->parent_fd.Get()) == 0 &&
                   ValidateLifecycleStagedFileReservationLock(reservation, lock);
  if (completed &&
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", completed_state))) {
    completed = false;
  }
  if (!completed) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
  }
  return result;
}
napi_value WriteLifecycleStagedFile(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value expected_size_value;
  napi_value bytes_value;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  uint32_t expected_size = 0U;
  SensitiveBytes bytes(0U);
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !GetRequiredProperty(env, options, "expectedSize", &expected_size_value) ||
      !GetRequiredProperty(env, options, "bytes", &bytes_value) ||
      !ParseLifecycleSize(env, expected_size_value, &expected_size) ||
      !ParseLifecycleBytes(env, bytes_value, &bytes) || !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state != LifecycleStagedFileReservationState::kOpen || reservation->sealed ||
      reservation->size != expected_size || !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  const uint64_t result_size = static_cast<uint64_t>(expected_size) + bytes.Size();
  if (result_size > kMaximumLifecycleWriteBytes ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock) ||
      !WriteLifecycleBytes(reservation->file_fd.Get(), expected_size, bytes) ||
      fsync(reservation->file_fd.Get()) != 0) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  reservation->size = result_size;
  if (!SealLifecycleStagedFileReservation(reservation, lock) ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}

bool RetainLifecycleStagedFileReservationForRecovery(LifecycleStagedFileReservation* reservation,
                                                     const LifecycleLock* lock) {
  return reservation != nullptr &&
         reservation->link_state == LifecycleReservationLinkState::kStage &&
         ValidateLifecycleStagedFileReservation(reservation) &&
         ValidateLifecycleStagedFileReservationLock(reservation, lock);
}
bool RetainLifecycleStagedDirectoryReservationForRecovery(
    LifecycleStagedDirectoryReservation* reservation, const LifecycleLock* lock) {
  return reservation != nullptr &&
         reservation->link_state == LifecycleReservationLinkState::kStage &&
         ValidateLifecycleStagedDirectoryReservation(reservation) &&
         ValidateLifecycleStagedDirectoryReservationLock(reservation, lock);
}
napi_value RetainReservationForRecovery(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value reservation_value;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "reservation", &reservation_value) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  bool is_file = false;
  bool is_directory = false;
  if (!IsNapiStatusOk(napi_check_object_type_tag(env, reservation_value,
                                                  &kLifecycleStagedFileReservationTypeTag, &is_file)) ||
      !IsNapiStatusOk(napi_check_object_type_tag(env, reservation_value,
                                                  &kLifecycleStagedDirectoryReservationTypeTag,
                                                  &is_directory))) {
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  if (is_file) {
    LifecycleStagedFileReservation* reservation = nullptr;
    if (!RequireLifecycleStagedFileReservation(env, reservation_value, &reservation)) {
      return nullptr;
    }
    const bool retained =
        RetainLifecycleStagedFileReservationForRecovery(reservation, lock) &&
        ValidateRetainedLifecycleWal(lock);
    if (retained) {
      reservation->state = LifecycleStagedFileReservationState::kClosed;
      CloseLifecycleStagedFileReservation(reservation);
      ClearRetainedLifecycleWal(lock);
    }
    return LifecycleResult(env, retained ? "completed" : "indeterminate");
  }
  if (is_directory) {
    LifecycleStagedDirectoryReservation* reservation = nullptr;
    if (!RequireLifecycleStagedDirectoryReservation(env, reservation_value, &reservation)) {
      return nullptr;
    }
    const bool retained =
        RetainLifecycleStagedDirectoryReservationForRecovery(reservation, lock) &&
        ValidateRetainedLifecycleWal(lock);
    if (retained) {
      reservation->state = LifecycleStagedDirectoryReservationState::kClosed;
      CloseLifecycleStagedDirectoryReservation(reservation);
      ClearRetainedLifecycleWal(lock);
    }
    return LifecycleResult(env, retained ? "completed" : "indeterminate");
  }
  ThrowLifecycleDenied(env);
  return nullptr;
}
napi_value PublishReservedLifecycleStagedFileNoReplace(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value target_path_value;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  std::string target_path;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !GetRequiredProperty(env, options, "targetPath", &target_path_value) ||
      !ParseLifecyclePath(env, target_path_value, &target_path) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state != LifecycleStagedFileReservationState::kOpen ||
      reservation->link_state != LifecycleReservationLinkState::kStage ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  FileDescriptor target_parent;
  std::string target_name;
  if (!OpenLifecycleParent(env, target_path, &target_parent, &target_name) ||
      !SameLifecycleDirectory(reservation->parent_fd.Get(), target_parent.Get())) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }
  if (!ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  if (RenameLifecycleNoReplace(reservation->parent_fd.Get(), reservation->name, target_name) !=
      LifecycleNoReplaceResult::kCompleted) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  reservation->name = std::move(target_name);
  reservation->link_state = LifecycleReservationLinkState::kPublished;
  reservation->state = LifecycleStagedFileReservationState::kPublished;
  if (!RefreshLifecycleStagedFileReservationSeal(reservation, lock) ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      fsync(reservation->parent_fd.Get()) != 0 ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}

napi_value ValidateLifecycleStagedFileReservation(napi_env env, napi_callback_info info) {
  napi_value options;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state != LifecycleStagedFileReservationState::kPublished ||
      reservation->link_state != LifecycleReservationLinkState::kPublished ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}
napi_value CloseLifecycleStagedFileReservation(napi_env env, napi_callback_info info) {
  napi_value options;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state == LifecycleStagedFileReservationState::kClosed) {
    return LifecycleLockedResult(env, lock);
  }
  if (reservation->state != LifecycleStagedFileReservationState::kPublished ||
      reservation->link_state != LifecycleReservationLinkState::kPublished ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  CloseLifecycleStagedFileReservation(reservation);
  reservation->state = LifecycleStagedFileReservationState::kClosed;
  return LifecycleLockedResult(env, lock);
}

napi_value DiscardLifecycleStagedFileReservation(napi_env env, napi_callback_info info) {
  napi_value options;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state == LifecycleStagedFileReservationState::kDiscarded) {
    return LifecycleLockedResult(env, lock);
  }
  if (reservation->state == LifecycleStagedFileReservationState::kPublished ||
      reservation->link_state == LifecycleReservationLinkState::kPublished) {
    return LifecycleResult(env, "indeterminate");
  }
  if ((reservation->state != LifecycleStagedFileReservationState::kOpen &&
       reservation->state != LifecycleStagedFileReservationState::kIndeterminate) ||
      !DiscardLifecycleReservationLink(
          reservation->parent_fd, reservation->parent_identity, reservation->file_fd.Get(),
          reservation->name, reservation->identity, false, lock)) {
    reservation->state = LifecycleStagedFileReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  reservation->state = LifecycleStagedFileReservationState::kDiscarded;
  CloseLifecycleStagedFileReservation(reservation);
  return LifecycleResult(env, "completed");
}
napi_value PublishLifecycleStagedFileNoReplace(napi_env env, napi_callback_info info) {
  std::string staging_path;
  std::string target_path;
  Identity identity{};
  mode_t mode = 0;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleNoReplaceOptions(env, info, &staging_path, &target_path, &identity, &mode) ||
      !RequireLifecycleLockArgument(env, info, &lock)) {
    return nullptr;
  }

  FileDescriptor staging_parent;
  FileDescriptor target_parent;
  std::string staging_name;
  std::string target_name;
  if (!OpenLifecycleParent(env, staging_path, &staging_parent, &staging_name) ||
      !OpenLifecycleParent(env, target_path, &target_parent, &target_name) ||
      !SameLifecycleDirectory(staging_parent.Get(), target_parent.Get()) ||
      !ValidateBoundedLifecycleFileAt(staging_parent.Get(), staging_name, identity, mode)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }
  if (!ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const LifecycleNoReplaceResult publication =
      RenameLifecycleNoReplace(staging_parent.Get(), staging_name, target_name);
  if (publication == LifecycleNoReplaceResult::kUnsupported) {
    return LifecycleResult(env, "indeterminate");
  }
  if (publication != LifecycleNoReplaceResult::kCompleted) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  if (!ValidateBoundedLifecycleFileAt(staging_parent.Get(), target_name, identity, mode)) {
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleResult(
      env, fsync(staging_parent.Get()) == 0 && ValidateLifecycleLock(lock) ? "completed"
                                                                            : "indeterminate");
}

bool LifecycleEntryAbsent(int parent_fd, const std::string& name) {
  struct stat stat{};
  return fstatat(parent_fd, name.c_str(), &stat, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}
bool CanCloseRestoredLifecycleMoveQuarantine(const LifecycleQuarantine* quarantine,
                                             const LifecycleLock* lock) {
  return quarantine != nullptr && ValidateLifecycleQuarantineLock(quarantine, lock) &&
         ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                          quarantine->quarantine_identity,
                                          quarantine->quarantine_mode) &&
         LifecycleEntryAbsent(quarantine->parent_fd.Get(), quarantine->quarantine_name) &&
         fsync(quarantine->parent_fd.Get()) == 0 &&
         ValidateLifecycleQuarantineLock(quarantine, lock);
}
bool CanCloseReversedLifecycleExchangeQuarantine(const LifecycleQuarantine* quarantine,
                                                 const LifecycleLock* lock) {
  struct stat held{};
  return quarantine != nullptr && fstat(quarantine->entry_fd.Get(), &held) == 0 &&
         SameIdentity(held, quarantine->quarantine_identity) &&
         ValidateLifecycleQuarantineLock(quarantine, lock) &&
         ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                          quarantine->quarantine_identity,
                                          quarantine->quarantine_mode) &&
         ValidateLifecycleQuarantineEntry(quarantine, quarantine->quarantine_name,
                                          quarantine->target_identity, quarantine->target_mode) &&
         fsync(quarantine->parent_fd.Get()) == 0 &&
         ValidateLifecycleQuarantineLock(quarantine, lock);
}
std::string LifecycleRemovalQuarantineName(const Identity& identity) {
  return ".scg-remove-" + std::to_string(identity.device) + "-" +
         std::to_string(identity.inode);
}

napi_value RemoveExactWal(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value target_value;
  LifecycleExactFileRecord target{};
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "target", &target_value) ||
      !ParseLifecycleExactFileRecord(env, target_value, &target) ||
      !ParseLifecycleExactWalSnapshot(env, target_value, &target) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  FileDescriptor parent;
  std::string name;
  if (!OpenLifecycleParent(env, target.path, &parent, &name) ||
      !ValidateRetainedLifecycleWalTarget(target, parent, name, lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const std::string quarantine_name = LifecycleRemovalQuarantineName(target.identity);
  if (quarantine_name == name) {
    return LifecycleResult(env, "indeterminate");
  }
  FileDescriptor quarantine_parent(dup(parent.Get()));
  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (quarantine_parent.Get() < 0) {
    return LifecycleResult(env, "indeterminate");
  }
  if (!CreateLifecycleQuarantine(env, lock, &quarantine_parent, name, quarantine_name,
                                 target.identity, target.identity, target.mode, target.mode,
                                 LifecycleQuarantineKind::kFile, LifecycleQuarantineOperation::kMove,
                                 &quarantine, &quarantine_value)) {
    return nullptr;
  }
  if (!ValidateRetainedLifecycleWalTarget(target, quarantine->parent_fd, name, lock)) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  const LifecycleExactMoveResult moved = MoveExactLifecycleEntryToQuarantine(
      quarantine->parent_fd.Get(), name, quarantine_name, target.identity, target.mode,
      LifecycleQuarantineKind::kFile, lock);
  if (moved == LifecycleExactMoveResult::kCompleted &&
      BindRetainedLifecycleQuarantineExactSnapshot(quarantine, target, lock)) {
    quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
    return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &target.identity,
                                             quarantine_value);
  }
  if (moved == LifecycleExactMoveResult::kRestoredForeign) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
}
napi_value RemoveExactCredential(napi_env env, napi_callback_info info) {
  LifecycleExactFileRecord target{};
  LifecycleLock* lock = nullptr;
  if (!ParseExactLifecycleAuthorityOptions(env, info, &target, &lock)) {
    return nullptr;
  }
  FileDescriptor parent;
  std::string name;
  FileDescriptor file;
  struct stat parent_stat{};
  struct stat opened{};
  struct stat linked{};
  if (target.mode != 0600 ||
      !OpenExactLifecycleFile(env, target, &parent, &name, &file, &opened, &linked) ||
      fstat(parent.Get(), &parent_stat) != 0 ||
      !ValidateLifecycleParent(parent, LifecycleIdentityFromStat(parent_stat)) ||
      !HasSafeAcl(file.Get()) ||
      !IsBoundedExactLifecycleFile(opened, target.identity, target.mode) ||
      !IsBoundedExactLifecycleFile(linked, target.identity, target.mode) ||
      !SameFileState(opened, linked) || !ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const std::string quarantine_name = LifecycleRemovalQuarantineName(target.identity);
  if (quarantine_name == name) {
    return LifecycleResult(env, "indeterminate");
  }
  FileDescriptor quarantine_parent(dup(parent.Get()));
  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (quarantine_parent.Get() < 0) {
    return LifecycleResult(env, "indeterminate");
  }
  if (!CreateLifecycleQuarantine(env, lock, &quarantine_parent, name, quarantine_name,
                                 target.identity, target.identity, target.mode, target.mode,
                                 LifecycleQuarantineKind::kFile, LifecycleQuarantineOperation::kMove,
                                 &quarantine, &quarantine_value)) {
    return nullptr;
  }
  const LifecycleExactMoveResult moved = MoveExactLifecycleEntryToQuarantine(
      quarantine->parent_fd.Get(), name, quarantine_name, target.identity, target.mode,
      LifecycleQuarantineKind::kFile, lock);
  if (moved == LifecycleExactMoveResult::kCompleted) {
    quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
    if (BindSelfLifecycleQuarantineSnapshot(quarantine, lock) &&
        ValidateRetainedLifecycleQuarantineEntry(quarantine, lock)) {
      return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &target.identity,
                                               quarantine_value);
    }
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  if (moved == LifecycleExactMoveResult::kRestoredForeign) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
}

napi_value RemoveExactStagedFile(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value target_value;
  LifecycleExactFileRecord target{};
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "target", &target_value) ||
      !ParseLifecycleExactFileRecord(env, target_value, &target) ||
      !ParseLifecycleExactContentSnapshot(env, target_value, &target) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  FileDescriptor parent;
  std::string name;
  if (!OpenLifecycleParent(env, target.path, &parent, &name)) {
    return LifecycleResult(env, "indeterminate");
  }
  FileDescriptor file(OpenFinalAt(parent.Get(), name));
  if (!ValidateExactLifecycleContentSnapshot(target, parent, name, file, lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const std::string quarantine_name = LifecycleRemovalQuarantineName(target.identity);
  if (quarantine_name == name) {
    return LifecycleResult(env, "indeterminate");
  }
  FileDescriptor quarantine_parent(dup(parent.Get()));
  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (quarantine_parent.Get() < 0) {
    return LifecycleResult(env, "indeterminate");
  }
  if (!CreateLifecycleQuarantine(env, lock, &quarantine_parent, name, quarantine_name,
                                 target.identity, target.identity, target.mode, target.mode,
                                 LifecycleQuarantineKind::kFile, LifecycleQuarantineOperation::kMove,
                                 &quarantine, &quarantine_value)) {
    return nullptr;
  }
  const LifecycleExactMoveResult moved = MoveExactLifecycleEntryToQuarantine(
      quarantine->parent_fd.Get(), name, quarantine_name, target.identity, target.mode,
      LifecycleQuarantineKind::kFile, lock);
  if (moved == LifecycleExactMoveResult::kCompleted &&
      BindRetainedLifecycleQuarantineExactSnapshot(quarantine, target, lock)) {
    quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
    return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &target.identity,
                                             quarantine_value);
  }
  if (moved == LifecycleExactMoveResult::kRestoredForeign) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
}


napi_value ReplaceLifecycleStagedFileExact(napi_env env, napi_callback_info info) {
  std::string staging_path;
  std::string target_path;
  Identity identity{};
  mode_t mode = 0;
  Identity target_identity{};
  mode_t target_mode = 0;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleReplaceOptions(env, info, &staging_path, &target_path, &identity, &mode,
                                    &target_identity, &target_mode) ||
      !RequireLifecycleLockArgument(env, info, &lock)) {
    return nullptr;
  }

  FileDescriptor staging_parent;
  FileDescriptor target_parent;
  std::string staging_name;
  std::string target_name;
  if (!OpenLifecycleParent(env, staging_path, &staging_parent, &staging_name) ||
      !OpenLifecycleParent(env, target_path, &target_parent, &target_name) ||
      !SameLifecycleDirectory(staging_parent.Get(), target_parent.Get()) ||
      !ValidateBoundedLifecycleFileAt(staging_parent.Get(), staging_name, identity, mode) ||
      !ValidateBoundedLifecycleFileAt(target_parent.Get(), target_name, target_identity,
                                      target_mode)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (!CreateLifecycleQuarantine(
          env, lock, &staging_parent, target_name, staging_name, identity, target_identity, mode,
          target_mode, LifecycleQuarantineKind::kFile, LifecycleQuarantineOperation::kExchange,
          &quarantine, &quarantine_value)) {
    return nullptr;
  }

  bool has_expectation = false;
  uint32_t expected_size = 0U;
  std::string expected_digest;
  {
    napi_value expectation_options;
    bool has_size = false;
    bool has_digest = false;
    if (!GetSingleObjectArgument(env, info, &expectation_options) ||
        !IsNapiStatusOk(
            napi_has_named_property(env, expectation_options, "targetSize", &has_size)) ||
        !IsNapiStatusOk(
            napi_has_named_property(env, expectation_options, "targetDigest", &has_digest))) {
      return nullptr;
    }
    if (has_size != has_digest) {
      ThrowLifecycleFailure(env);
      return nullptr;
    }
    if (has_size) {
      napi_value size_value;
      napi_value digest_value;
      if (!GetRequiredProperty(env, expectation_options, "targetSize", &size_value) ||
          !GetRequiredProperty(env, expectation_options, "targetDigest", &digest_value) ||
          !ParseLifecycleSize(env, size_value, &expected_size) ||
          !GetString(env, digest_value, &expected_digest, 71U)) {
        return nullptr;
      }
      if (!IsSha256Digest(expected_digest)) {
        ThrowLifecycleFailure(env);
        return nullptr;
      }
      has_expectation = true;
    }
  }
  if (!ValidateLifecycleQuarantineLock(quarantine, lock)) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  const LifecycleExchangeResult replacement =
      ExchangeLifecycleEntries(quarantine->parent_fd.Get(), staging_name, target_name);
  if (replacement != LifecycleExchangeResult::kCompleted) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
  const bool target_matches =
      ValidateLifecycleQuarantineEntry(quarantine, target_name, identity, mode);
  const bool quarantine_matches =
      ValidateLifecycleQuarantineEntry(quarantine, staging_name, target_identity, target_mode);
  bool bound = true;
  if (has_expectation) {
    const LifecycleExactFileRecord expectation_record{
        .identity = target_identity,
        .mode = target_mode,
        .has_content_snapshot = true,
        .expected_size = expected_size,
        .expected_digest = expected_digest,
    };
    bound = BindRetainedLifecycleQuarantineExactSnapshot(quarantine, expectation_record, lock);
  }
  if (target_matches && quarantine_matches && bound &&
      ValidateRetainedLifecycleQuarantineEntry(quarantine, lock) &&
      fsync(quarantine->parent_fd.Get()) == 0 &&
      ValidateLifecycleQuarantineLock(quarantine, lock)) {
    return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &target_identity,
                                             quarantine_value);
  }
  return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
}
napi_value ReplaceReservedLifecycleOrdinaryFileExact(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value target_path_value;
  napi_value target_identity_value;
  napi_value target_mode_value;
  napi_value target_size_value;
  napi_value target_digest_value;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  std::string target_path;
  Identity target_identity{};
  mode_t target_mode = 0;
  uint32_t target_size = 0U;
  std::string target_digest;
  LifecycleExactFileRecord target{};
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !GetRequiredProperty(env, options, "targetPath", &target_path_value) ||
      !GetRequiredProperty(env, options, "targetIdentity", &target_identity_value) ||
      !GetRequiredProperty(env, options, "targetMode", &target_mode_value) ||
      !GetRequiredProperty(env, options, "targetSize", &target_size_value) ||
      !GetRequiredProperty(env, options, "targetDigest", &target_digest_value) ||
      !ParseLifecyclePath(env, target_path_value, &target_path) ||
      !ParseIdentity(env, target_identity_value, &target_identity) ||
      !ParseLifecycleMode(env, target_mode_value, &target_mode) ||
      !ParseLifecycleSize(env, target_size_value, &target_size) ||
      !GetString(env, target_digest_value, &target_digest, 71U) ||
      !IsSha256Digest(target_digest) || !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  target.path = target_path;
  target.identity = target_identity;
  target.mode = target_mode;
  target.has_content_snapshot = true;
  target.expected_size = target_size;
  target.expected_digest = std::move(target_digest);
  if (reservation->state != LifecycleStagedFileReservationState::kOpen ||
      reservation->link_state != LifecycleReservationLinkState::kStage || !reservation->sealed ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  FileDescriptor target_parent;
  std::string target_name;
  if (!OpenLifecycleParent(env, target_path, &target_parent, &target_name) ||
      !SameLifecycleDirectory(reservation->parent_fd.Get(), target_parent.Get())) {
    return LifecycleResult(env, "indeterminate");
  }
  const Identity reservation_identity = reservation->identity;
  const mode_t reservation_mode = reservation->mode;
  const std::string reservation_name = reservation->name;
  FileDescriptor quarantine_parent(dup(reservation->parent_fd.Get()));
  if (quarantine_parent.Get() < 0) {
    return LifecycleResult(env, "indeterminate");
  }
  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (!CreateLifecycleQuarantine(
          env, lock, &quarantine_parent, target_name, reservation_name, reservation_identity,
          target_identity, reservation_mode, target_mode, LifecycleQuarantineKind::kFile,
          LifecycleQuarantineOperation::kExchange, &quarantine, &quarantine_value)) {
    return nullptr;
  }
  if (!ValidateExactLifecycleContentSnapshot(target, target_parent, target_name,
                                             quarantine->entry_fd, lock) ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  if (ExchangeLifecycleEntries(quarantine->parent_fd.Get(), reservation_name, target_name) !=
      LifecycleExchangeResult::kCompleted) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  reservation->name = target_name;
  reservation->link_state = LifecycleReservationLinkState::kPublished;
  reservation->state = LifecycleStagedFileReservationState::kPublished;
  quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
  LifecycleExactFileRecord moved_target = target;
  if (!RefreshLifecycleStagedFileReservationSeal(reservation, lock) ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !BindPostExchangeLifecycleExactSnapshot(&moved_target, quarantine->parent_fd,
                                              reservation_name, quarantine->entry_fd, lock) ||
      !BindRetainedLifecycleQuarantineExactSnapshot(quarantine, moved_target, lock) ||
      fsync(quarantine->parent_fd.Get()) != 0 ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateRetainedLifecycleQuarantineEntry(quarantine, lock) ||
      !ValidateLifecycleQuarantineLock(quarantine, lock)) {
    CloseLifecycleStagedFileReservation(reservation);
    reservation->state = LifecycleStagedFileReservationState::kClosed;
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  CloseLifecycleStagedFileReservation(reservation);
  reservation->state = LifecycleStagedFileReservationState::kClosed;
  return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &target_identity,
                                           quarantine_value);
}

napi_value ReplaceReservedLifecycleFileExact(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value target_path_value;
  napi_value target_identity_value;
  napi_value target_mode_value;
  napi_value discard_replaced_target_value;
  napi_value target_size_value;
  napi_value target_digest_value;
  napi_value target_stat_value;
  LifecycleStagedFileReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  std::string target_path;
  Identity target_identity{};
  mode_t target_mode = 0;
  bool discard_replaced_target = false;
  napi_valuetype discard_replaced_target_type;
  uint32_t target_size = 0U;
  std::string target_digest;
  LifecycleExactFileRecord target{};
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedFileReservation(env, options, &reservation) ||
      !GetRequiredProperty(env, options, "targetPath", &target_path_value) ||
      !GetRequiredProperty(env, options, "targetIdentity", &target_identity_value) ||
      !GetRequiredProperty(env, options, "targetMode", &target_mode_value) ||
      !GetRequiredProperty(env, options, "targetSize", &target_size_value) ||
      !GetRequiredProperty(env, options, "targetDigest", &target_digest_value) ||
      !GetRequiredProperty(env, options, "targetStat", &target_stat_value) ||
      !GetRequiredProperty(env, options, "discardReplacedTarget", &discard_replaced_target_value) ||
      !ParseLifecyclePath(env, target_path_value, &target_path) ||
      !ParseIdentity(env, target_identity_value, &target_identity) ||
      !ParseLifecycleMode(env, target_mode_value, &target_mode) ||
      !ParseLifecycleSize(env, target_size_value, &target_size) ||
      !GetString(env, target_digest_value, &target_digest, 71U) || !IsSha256Digest(target_digest) ||
      !GetString(env, target_stat_value, &target.expected_stat, 256U) ||
      target.expected_stat.empty() ||
      !IsNapiStatusOk(napi_typeof(env, discard_replaced_target_value,
                                  &discard_replaced_target_type)) ||
      discard_replaced_target_type != napi_boolean ||
      !IsNapiStatusOk(napi_get_value_bool(env, discard_replaced_target_value,
                                           &discard_replaced_target)) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (discard_replaced_target) {
    ThrowLifecycleDenied(env);
    return nullptr;
  }
  target.path = target_path;
  target.identity = target_identity;
  target.mode = target_mode;
  target.has_content_snapshot = true;
  target.expected_size = target_size;
  target.expected_digest = std::move(target_digest);
  target.has_stat_snapshot = true;
  if (reservation->state != LifecycleStagedFileReservationState::kOpen ||
      reservation->link_state != LifecycleReservationLinkState::kStage || !reservation->sealed ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  FileDescriptor target_parent;
  std::string target_name;
  if (!OpenLifecycleParent(env, target_path, &target_parent, &target_name) ||
      !SameLifecycleDirectory(reservation->parent_fd.Get(), target_parent.Get()) ||
      !ValidateRetainedLifecycleWalTarget(target, target_parent, target_name, lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const Identity reservation_identity = reservation->identity;
  const mode_t reservation_mode = reservation->mode;
  const std::string reservation_name = reservation->name;
  FileDescriptor quarantine_parent(dup(reservation->parent_fd.Get()));
  if (quarantine_parent.Get() < 0) {
    return LifecycleResult(env, "indeterminate");
  }
  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (!CreateLifecycleQuarantine(
          env, lock, &quarantine_parent, target_name, reservation_name, reservation_identity,
          target_identity, reservation_mode, target_mode, LifecycleQuarantineKind::kFile,
          LifecycleQuarantineOperation::kExchange, &quarantine, &quarantine_value)) {
    return nullptr;
  }
  if (!ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateLifecycleStagedFileReservationLock(reservation, lock) ||
      !ValidateRetainedLifecycleWalTarget(target, target_parent, target_name, lock)) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  if (ExchangeLifecycleEntries(quarantine->parent_fd.Get(), reservation_name, target_name) !=
      LifecycleExchangeResult::kCompleted) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  reservation->name = target_name;
  reservation->link_state = LifecycleReservationLinkState::kPublished;
  reservation->state = LifecycleStagedFileReservationState::kPublished;
  quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
  LifecycleExactFileRecord moved_target = target;
  if (!RefreshLifecycleStagedFileReservationSeal(reservation, lock) ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !BindPostExchangeLifecycleExactSnapshot(&moved_target, quarantine->parent_fd,
                                              reservation_name, lock->retained_wal_file_fd, lock) ||
      !BindRetainedLifecycleQuarantineExactSnapshot(quarantine, moved_target, lock) ||
      fsync(quarantine->parent_fd.Get()) != 0 ||
      !ValidateLifecycleStagedFileReservation(reservation) ||
      !ValidateRetainedLifecycleQuarantineEntry(quarantine, lock) ||
      !ValidateLifecycleQuarantineLock(quarantine, lock)) {
    CloseLifecycleStagedFileReservation(reservation);
    reservation->state = LifecycleStagedFileReservationState::kClosed;
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  CloseLifecycleStagedFileReservation(reservation);
  reservation->state = LifecycleStagedFileReservationState::kClosed;
  return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &target_identity,
                                           quarantine_value);
}

napi_value QuarantineLifecycleExactFileBinding(napi_env env, napi_callback_info info,
                                               bool require_credential) {
  std::string path;
  std::string quarantine_path;
  Identity identity{};
  mode_t mode = 0;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleQuarantineOptions(env, info, &path, &quarantine_path, &identity, &mode) ||
      !RequireLifecycleLockArgument(env, info, &lock)) {
    return nullptr;
  }
  bool has_expectation = false;
  uint32_t expected_size = 0U;
  std::string expected_digest;
  {
    napi_value expectation_options;
    bool has_size = false;
    bool has_digest = false;
    if (!GetSingleObjectArgument(env, info, &expectation_options) ||
        !IsNapiStatusOk(
            napi_has_named_property(env, expectation_options, "expectedSize", &has_size)) ||
        !IsNapiStatusOk(
            napi_has_named_property(env, expectation_options, "expectedDigest", &has_digest))) {
      return nullptr;
    }
    if (has_size != has_digest || (require_credential && has_size)) {
      ThrowLifecycleFailure(env);
      return nullptr;
    }
    if (has_size) {
      napi_value size_value;
      napi_value digest_value;
      if (!GetRequiredProperty(env, expectation_options, "expectedSize", &size_value) ||
          !GetRequiredProperty(env, expectation_options, "expectedDigest", &digest_value) ||
          !ParseLifecycleSize(env, size_value, &expected_size) ||
          !GetString(env, digest_value, &expected_digest, 71U)) {
        return nullptr;
      }
      if (!IsSha256Digest(expected_digest)) {
        ThrowLifecycleFailure(env);
        return nullptr;
      }
      has_expectation = true;
    }
  }

  FileDescriptor parent;
  FileDescriptor quarantine_parent;
  std::string name;
  std::string quarantine_name;
  if ((require_credential && mode != 0600) ||
      !OpenLifecycleParent(env, path, &parent, &name) ||
      !OpenLifecycleParent(env, quarantine_path, &quarantine_parent, &quarantine_name) ||
      !SameLifecycleDirectory(parent.Get(), quarantine_parent.Get()) ||
      !ValidateBoundedLifecycleFileAt(parent.Get(), name, identity, mode)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (!CreateLifecycleQuarantine(
          env, lock, &parent, name, quarantine_name, identity, identity, mode, mode,
          LifecycleQuarantineKind::kFile, LifecycleQuarantineOperation::kMove, &quarantine,
          &quarantine_value)) {
    return nullptr;
  }

  const LifecycleExactMoveResult moved = MoveExactLifecycleEntryToQuarantine(
      quarantine->parent_fd.Get(), name, quarantine_name, identity, mode,
      LifecycleQuarantineKind::kFile, lock);
  if (moved == LifecycleExactMoveResult::kCompleted) {
    quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
    bool bound = true;
    if (require_credential) {
      bound = BindSelfLifecycleQuarantineSnapshot(quarantine, lock);
    } else if (has_expectation) {
      const LifecycleExactFileRecord expectation_record{
          .identity = identity,
          .mode = mode,
          .has_content_snapshot = true,
          .expected_size = expected_size,
          .expected_digest = expected_digest,
      };
      bound = BindRetainedLifecycleQuarantineExactSnapshot(quarantine, expectation_record, lock);
    }
    if (!bound) {
      return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
    }
    return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &identity, quarantine_value);
  }
  if (moved == LifecycleExactMoveResult::kRestoredForeign) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
}
napi_value QuarantineLifecycleExactFile(napi_env env, napi_callback_info info) {
  return QuarantineLifecycleExactFileBinding(env, info, false);
}
napi_value QuarantineLifecycleExactCredential(napi_env env, napi_callback_info info) {
  return QuarantineLifecycleExactFileBinding(env, info, true);
}


napi_value ReserveDirectoryFromIntent(napi_env env, napi_callback_info info) {
  mode_t mode = 0;
  LifecycleCreationIntent* intent = nullptr;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleReserveFromIntentOptions(env, info, &mode, &intent, &lock)) {
    return nullptr;
  }
  if (intent->kind != LifecycleCreationIntentKind::kDirectory ||
      !RefreshLifecycleCreationIntentAuthority(intent, lock)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  const bool intent_prepared = intent->prepared && ValidateLifecycleCreationIntent(intent, lock);
  const Identity identity = intent->marker_identity;
  auto* reservation = new (std::nothrow) LifecycleStagedDirectoryReservation{
      .parent_fd = FileDescriptor(),
      .directory_fd = FileDescriptor(),
      .parent_identity = intent->parent_identity,
      .identity = identity,
      .lock_identity = intent->lock_identity,
      .lock_session_generation = intent->lock_session_generation,
      .name = intent->marker_name,
      .mode = mode,
  };
  if (reservation == nullptr) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, true, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    ThrowLifecycleFailure(env);
    return nullptr;
  }

  napi_value reservation_value;
  if (!IsNapiStatusOk(napi_create_object(env, &reservation_value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, reservation_value,
                                            &kLifecycleStagedDirectoryReservationTypeTag)) ||
      !IsNapiStatusOk(napi_wrap(env, reservation_value, reservation,
                                 FinalizeLifecycleStagedDirectoryReservation, nullptr, nullptr))) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, true, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    delete reservation;
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  napi_value result;
  napi_value completed_state;
  if (!CreateLifecycleMutationResult(env, "indeterminate", &identity, &result)) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, true, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    return nullptr;
  }
  if (!IsNapiStatusOk(napi_create_string_utf8(env, "completed", NAPI_AUTO_LENGTH, &completed_state)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "reservation", reservation_value))) {
    if (DiscardLifecycleReservationLink(
            intent->parent_fd, intent->parent_identity, intent->marker_fd.Get(),
            intent->marker_name, intent->marker_identity, true, lock)) {
      intent->consumed = true;
      CloseLifecycleCreationIntent(intent);
    }
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  reservation->parent_fd = std::move(intent->parent_fd);
  reservation->directory_fd = std::move(intent->marker_fd);
  reservation->slot_charged = true;
  intent->consumed = true;
  intent->slot_charged = false;
  CloseLifecycleCreationIntent(intent);

  const bool renamed =
      intent_prepared &&
      ValidateLifecycleReservationLink(reservation->parent_fd, reservation->parent_identity,
                                       reservation->directory_fd.Get(), reservation->name,
                                       reservation->identity, true) &&
      ValidateLifecycleStagedDirectoryReservationLock(reservation, lock) &&
      RenameLifecycleNoReplace(reservation->parent_fd.Get(), reservation->name, intent->stage_name) ==
          LifecycleNoReplaceResult::kCompleted;
  if (renamed) {
    reservation->name = intent->stage_name;
    reservation->link_state = LifecycleReservationLinkState::kStage;
  }
  bool completed = renamed && fchmod(reservation->directory_fd.Get(), mode) == 0 &&
                   ClearInheritedAcl(reservation->directory_fd.Get()) &&
                   fsync(reservation->directory_fd.Get()) == 0 &&
                   ValidateLifecycleStagedDirectoryReservation(reservation) &&
                   fsync(reservation->parent_fd.Get()) == 0 &&
                   ValidateLifecycleStagedDirectoryReservationLock(reservation, lock);
  if (completed &&
      !IsNapiStatusOk(napi_set_named_property(env, result, "state", completed_state))) {
    completed = false;
  }
  if (!completed) {
    reservation->state = LifecycleStagedDirectoryReservationState::kIndeterminate;
  }
  return result;
}
napi_value PublishReservedLifecycleStagedDirectoryNoReplace(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value target_path_value;
  LifecycleStagedDirectoryReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  std::string target_path;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedDirectoryReservation(env, options, &reservation) ||
      !GetRequiredProperty(env, options, "targetPath", &target_path_value) ||
      !ParseLifecyclePath(env, target_path_value, &target_path) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state != LifecycleStagedDirectoryReservationState::kOpen ||
      reservation->link_state != LifecycleReservationLinkState::kStage ||
      !ValidateLifecycleStagedDirectoryReservation(reservation) ||
      !ValidateLifecycleStagedDirectoryReservationLock(reservation, lock)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  FileDescriptor target_parent;
  std::string target_name;
  if (!OpenLifecycleParent(env, target_path, &target_parent, &target_name) ||
      !SameLifecycleDirectory(reservation->parent_fd.Get(), target_parent.Get())) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }
  if (!ValidateLifecycleStagedDirectoryReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedDirectoryReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  if (RenameLifecycleNoReplace(reservation->parent_fd.Get(), reservation->name, target_name) !=
      LifecycleNoReplaceResult::kCompleted) {
    reservation->state = LifecycleStagedDirectoryReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  reservation->name = std::move(target_name);
  reservation->link_state = LifecycleReservationLinkState::kPublished;
  reservation->state = LifecycleStagedDirectoryReservationState::kPublished;
  if (!ValidateLifecycleStagedDirectoryReservation(reservation) ||
      fsync(reservation->parent_fd.Get()) != 0 ||
      !ValidateLifecycleStagedDirectoryReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedDirectoryReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleLockedResult(env, lock);
}

napi_value CloseLifecycleStagedDirectoryReservation(napi_env env, napi_callback_info info) {
  napi_value options;
  LifecycleStagedDirectoryReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedDirectoryReservation(env, options, &reservation) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state == LifecycleStagedDirectoryReservationState::kClosed) {
    return LifecycleLockedResult(env, lock);
  }
  if (reservation->state != LifecycleStagedDirectoryReservationState::kPublished ||
      reservation->link_state != LifecycleReservationLinkState::kPublished ||
      !ValidateLifecycleStagedDirectoryReservation(reservation) ||
      !ValidateLifecycleStagedDirectoryReservationLock(reservation, lock)) {
    reservation->state = LifecycleStagedDirectoryReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  CloseLifecycleStagedDirectoryReservation(reservation);
  reservation->state = LifecycleStagedDirectoryReservationState::kClosed;
  return LifecycleLockedResult(env, lock);
}

napi_value DiscardLifecycleStagedDirectoryReservation(napi_env env, napi_callback_info info) {
  napi_value options;
  LifecycleStagedDirectoryReservation* reservation = nullptr;
  LifecycleLock* lock = nullptr;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !ParseLifecycleStagedDirectoryReservation(env, options, &reservation) ||
      !ParseLifecycleLock(env, options, &lock)) {
    return nullptr;
  }
  if (reservation->state == LifecycleStagedDirectoryReservationState::kDiscarded) {
    return LifecycleLockedResult(env, lock);
  }
  if (reservation->state == LifecycleStagedDirectoryReservationState::kPublished ||
      reservation->link_state == LifecycleReservationLinkState::kPublished) {
    return LifecycleResult(env, "indeterminate");
  }
  if ((reservation->state != LifecycleStagedDirectoryReservationState::kOpen &&
       reservation->state != LifecycleStagedDirectoryReservationState::kIndeterminate) ||
      !IsEmptyLifecycleDirectory(reservation->directory_fd.Get()) ||
      !DiscardLifecycleReservationLink(
          reservation->parent_fd, reservation->parent_identity, reservation->directory_fd.Get(),
          reservation->name, reservation->identity, true, lock)) {
    reservation->state = LifecycleStagedDirectoryReservationState::kIndeterminate;
    return LifecycleResult(env, "indeterminate");
  }
  reservation->state = LifecycleStagedDirectoryReservationState::kDiscarded;
  CloseLifecycleStagedDirectoryReservation(reservation);
  return LifecycleResult(env, "completed");
}
napi_value PublishLifecycleStagedDirectoryNoReplace(napi_env env, napi_callback_info info) {
  std::string staging_path;
  std::string target_path;
  Identity identity{};
  mode_t mode = 0;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleNoReplaceOptions(env, info, &staging_path, &target_path, &identity, &mode) ||
      !RequireLifecycleLockArgument(env, info, &lock)) {
    return nullptr;
  }

  FileDescriptor staging_parent;
  FileDescriptor target_parent;
  std::string staging_name;
  std::string target_name;
  if (!OpenLifecycleParent(env, staging_path, &staging_parent, &staging_name) ||
      !OpenLifecycleParent(env, target_path, &target_parent, &target_name) ||
      !SameLifecycleDirectory(staging_parent.Get(), target_parent.Get()) ||
      !ValidateLifecycleDirectoryAt(staging_parent.Get(), staging_name, identity, mode)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }
  if (!ValidateLifecycleLock(lock)) {
    return LifecycleResult(env, "indeterminate");
  }
  const LifecycleNoReplaceResult publication =
      RenameLifecycleNoReplace(staging_parent.Get(), staging_name, target_name);
  if (publication == LifecycleNoReplaceResult::kUnsupported) {
    return LifecycleResult(env, "indeterminate");
  }
  if (publication != LifecycleNoReplaceResult::kCompleted) {
    ThrowLifecycleFailure(env);
    return nullptr;
  }
  if (!ValidateLifecycleDirectoryAt(staging_parent.Get(), target_name, identity, mode)) {
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleResult(
      env, fsync(staging_parent.Get()) == 0 && ValidateLifecycleLock(lock) ? "completed"
                                                                            : "indeterminate");
}

napi_value QuarantineLifecycleExactDirectory(napi_env env, napi_callback_info info) {
  std::string path;
  std::string quarantine_path;
  Identity identity{};
  mode_t mode = 0;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleQuarantineOptions(env, info, &path, &quarantine_path, &identity, &mode) ||
      !RequireLifecycleLockArgument(env, info, &lock)) {
    return nullptr;
  }

  FileDescriptor parent;
  FileDescriptor quarantine_parent;
  std::string name;
  std::string quarantine_name;
  if (!OpenLifecycleParent(env, path, &parent, &name) ||
      !OpenLifecycleParent(env, quarantine_path, &quarantine_parent, &quarantine_name) ||
      !SameLifecycleDirectory(parent.Get(), quarantine_parent.Get())) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  FileDescriptor directory(OpenDirectoryAt(parent.Get(), name));
  if (directory.Get() < 0 ||
      !ValidateLifecycleLinkedDirectory(parent.Get(), name, directory.Get(), identity, mode) ||
      !IsEmptyLifecycleDirectory(directory.Get()) ||
      !ValidateLifecycleLinkedDirectory(parent.Get(), name, directory.Get(), identity, mode)) {
    ThrowLifecycleIdentityMismatch(env);
    return nullptr;
  }

  napi_value quarantine_value;
  LifecycleQuarantine* quarantine = nullptr;
  if (!CreateLifecycleQuarantine(
          env, lock, &parent, name, quarantine_name, identity, identity, mode, mode,
          LifecycleQuarantineKind::kDirectory, LifecycleQuarantineOperation::kMove, &quarantine,
          &quarantine_value)) {
    return nullptr;
  }

  const LifecycleExactMoveResult moved = MoveExactLifecycleEntryToQuarantine(
      quarantine->parent_fd.Get(), name, quarantine_name, identity, mode,
      LifecycleQuarantineKind::kDirectory, lock);
  if (moved == LifecycleExactMoveResult::kCompleted) {
    quarantine->phase = LifecycleQuarantinePhase::kAtQuarantine;
    return LifecycleQuarantineDetailedResult(env, "completed", nullptr, &identity, quarantine_value);
  }
  if (moved == LifecycleExactMoveResult::kRestoredForeign) {
    CloseLifecycleQuarantine(quarantine);
    return LifecycleResult(env, "indeterminate");
  }
  return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
}
bool ValidateRetainedLifecycleQuarantineAtTarget(const LifecycleQuarantine* quarantine,
                                                 const LifecycleLock* lock) {
  if (quarantine == nullptr || quarantine->phase != LifecycleQuarantinePhase::kAtTarget ||
      quarantine->entry_fd.Get() < 0 || !ValidateLifecycleQuarantineLock(quarantine, lock)) {
    return false;
  }
  struct stat held{};
  if (fstat(quarantine->entry_fd.Get(), &held) != 0 ||
      !SameIdentity(held, quarantine->quarantine_identity) ||
      !ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                        quarantine->quarantine_identity,
                                        quarantine->quarantine_mode)) {
    return false;
  }
  if (quarantine->operation == LifecycleQuarantineOperation::kMove) {
    return LifecycleEntryAbsent(quarantine->parent_fd.Get(), quarantine->quarantine_name);
  }
  return ValidateLifecycleQuarantineEntry(quarantine, quarantine->quarantine_name,
                                          quarantine->target_identity,
                                          quarantine->target_mode);
}
napi_value FinalizeLifecycleQuarantineBinding(napi_env env, napi_callback_info info) {
  napi_value quarantine_value;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleQuarantineHandle(env, info, &quarantine_value) ||
      !RequireLifecycleLockArgument(env, info, &lock)) {
    return nullptr;
  }
  LifecycleQuarantine* quarantine = nullptr;
  if (!RequireLifecycleQuarantine(env, quarantine_value, &quarantine)) {
    return nullptr;
  }
  if (!ValidateLifecycleQuarantineLock(quarantine, lock)) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  if (quarantine->state == LifecycleQuarantineState::kFinalized) {
    return LifecycleLockedResult(env, lock);
  }
  if (quarantine->state != LifecycleQuarantineState::kActive &&
      quarantine->state != LifecycleQuarantineState::kIndeterminate) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  if (quarantine->phase == LifecycleQuarantinePhase::kPrepared) {
    struct stat held{};
    if (fstat(quarantine->entry_fd.Get(), &held) != 0 ||
        !SameIdentity(held, quarantine->quarantine_identity) ||
        !ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                          quarantine->quarantine_identity,
                                          quarantine->quarantine_mode) ||
        !LifecycleEntryAbsent(quarantine->parent_fd.Get(), quarantine->quarantine_name) ||
        !ValidateLifecycleQuarantineLock(quarantine, lock)) {
      return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
    }
    quarantine->state = LifecycleQuarantineState::kFinalized;
    CloseLifecycleQuarantine(quarantine);
    return LifecycleLockedResult(env, lock);
  }
  if (quarantine->phase == LifecycleQuarantinePhase::kUnlinked) {
    if (fsync(quarantine->parent_fd.Get()) != 0 ||
        !ValidateLifecycleQuarantineLock(quarantine, lock)) {
      return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
    }
    quarantine->state = LifecycleQuarantineState::kFinalized;
    CloseLifecycleQuarantine(quarantine);
    return LifecycleLockedResult(env, lock);
  }
  if (quarantine->phase != LifecycleQuarantinePhase::kAtQuarantine ||
      (quarantine->kind == LifecycleQuarantineKind::kFile &&
       !quarantine->has_content_snapshot) ||
      !ValidateRetainedLifecycleQuarantineEntry(quarantine, lock) ||
      (quarantine->operation == LifecycleQuarantineOperation::kExchange &&
       !ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                         quarantine->target_identity, quarantine->target_mode))) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  const int unlink_flags =
      quarantine->kind == LifecycleQuarantineKind::kDirectory ? AT_REMOVEDIR : 0;
  if (unlinkat(quarantine->parent_fd.Get(), quarantine->quarantine_name.c_str(), unlink_flags) !=
      0) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  quarantine->phase = LifecycleQuarantinePhase::kUnlinked;
  if (!LifecycleEntryAbsent(quarantine->parent_fd.Get(), quarantine->quarantine_name) ||
      fsync(quarantine->parent_fd.Get()) != 0 ||
      !ValidateLifecycleQuarantineLock(quarantine, lock)) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  quarantine->state = LifecycleQuarantineState::kFinalized;
  CloseLifecycleQuarantine(quarantine);
  return LifecycleLockedResult(env, lock);
}
napi_value RestoreLifecycleQuarantineBinding(napi_env env, napi_callback_info info) {
  napi_value quarantine_value;
  LifecycleLock* lock = nullptr;
  if (!ParseLifecycleQuarantineHandle(env, info, &quarantine_value) ||
      !RequireLifecycleLockArgument(env, info, &lock)) {
    return nullptr;
  }
  LifecycleQuarantine* quarantine = nullptr;
  if (!RequireLifecycleQuarantine(env, quarantine_value, &quarantine)) {
    return nullptr;
  }
  if (!ValidateLifecycleQuarantineLock(quarantine, lock)) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  if (quarantine->state == LifecycleQuarantineState::kRestored) {
    return LifecycleLockedResult(env, lock);
  }
  if (quarantine->state != LifecycleQuarantineState::kActive &&
      quarantine->state != LifecycleQuarantineState::kIndeterminate) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  if (quarantine->phase == LifecycleQuarantinePhase::kAtTarget) {
    if (!RefreshRetainedLifecycleQuarantineExactSnapshotAtName(
            quarantine, quarantine->target_name, lock) ||
        !ValidateRetainedLifecycleQuarantineAtTarget(quarantine, lock) ||
        (quarantine->operation == LifecycleQuarantineOperation::kMove
             ? !CanCloseRestoredLifecycleMoveQuarantine(quarantine, lock)
             : !CanCloseReversedLifecycleExchangeQuarantine(quarantine, lock))) {
      return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
    }
    quarantine->state = LifecycleQuarantineState::kRestored;
    CloseLifecycleQuarantine(quarantine);
    return LifecycleLockedResult(env, lock);
  }
  if (quarantine->phase != LifecycleQuarantinePhase::kAtQuarantine ||
      !ValidateRetainedLifecycleQuarantineEntry(quarantine, lock)) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }

  if (quarantine->operation == LifecycleQuarantineOperation::kExchange) {
    if (!ValidateLifecycleQuarantineEntry(quarantine, quarantine->target_name,
                                          quarantine->target_identity, quarantine->target_mode) ||
        ExchangeLifecycleEntries(quarantine->parent_fd.Get(), quarantine->quarantine_name,
                                 quarantine->target_name) != LifecycleExchangeResult::kCompleted) {
      return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
    }
  } else if (RenameLifecycleNoReplace(quarantine->parent_fd.Get(), quarantine->quarantine_name,
                                      quarantine->target_name) !=
             LifecycleNoReplaceResult::kCompleted) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  quarantine->phase = LifecycleQuarantinePhase::kAtTarget;
  if (!RefreshRetainedLifecycleQuarantineExactSnapshotAtName(quarantine, quarantine->target_name,
                                                              lock) ||
      !ValidateRetainedLifecycleQuarantineAtTarget(quarantine, lock) ||
      (quarantine->operation == LifecycleQuarantineOperation::kMove
           ? !CanCloseRestoredLifecycleMoveQuarantine(quarantine, lock)
           : !CanCloseReversedLifecycleExchangeQuarantine(quarantine, lock))) {
    return LifecycleQuarantineIndeterminate(env, quarantine, quarantine_value);
  }
  quarantine->state = LifecycleQuarantineState::kRestored;
  CloseLifecycleQuarantine(quarantine);
  return LifecycleLockedResult(env, lock);
}
bool ParseViteCacheRecord(napi_env env, napi_value value, ViteCacheRecord* output) {
  napi_value object;
  napi_value identity;
  napi_value device;
  napi_value owner;
  napi_value mode;
  napi_value uid;
  napi_value gid;
  uint32_t parsed_uid = 0;
  uint32_t parsed_gid = 0;
  uint32_t parsed_mode = 0;
  std::string record_device;
  if (!GetObject(env, value, &object) || !GetRequiredProperty(env, object, "identity", &identity) ||
      !GetRequiredProperty(env, object, "canonicalPath", &device) ||
      !ParseCanonicalAbsolutePath(env, device, &output->canonical_path) ||
      !GetRequiredProperty(env, object, "device", &device) ||
      !GetString(env, device, &record_device, kMaximumIdentityDecimalBytes) ||
      !ParseDecimalIdentityPart(env, device, &output->identity.device) ||
      !GetRequiredProperty(env, object, "owner", &owner) || !GetObject(env, owner, &owner) ||
      !GetRequiredProperty(env, owner, "uid", &uid) || !GetRequiredProperty(env, owner, "gid", &gid) ||
      !GetUint32(env, uid, UINT32_MAX, &parsed_uid) || !GetUint32(env, gid, UINT32_MAX, &parsed_gid) ||
      !GetRequiredProperty(env, object, "mode", &mode) || !GetUint32(env, mode, 07777U, &parsed_mode) ||
      !ParseIdentity(env, identity, &output->identity)) {
    return false;
  }
  if (record_device != std::to_string(output->identity.device) || parsed_mode != 0700U) {
    ThrowCacheDenied(env);
    return false;
  }
  output->uid = static_cast<uid_t>(parsed_uid);
  output->gid = static_cast<gid_t>(parsed_gid);
  output->mode = static_cast<mode_t>(parsed_mode);
  return true;
}

bool SameIdentity(const Identity& left, const Identity& right) {
  return left.device == right.device && left.inode == right.inode;
}

bool IsCanonicalChildPath(const std::string& parent, const std::string& child) {
  if (parent == "/") {
    if (child.size() < 2U || child[0] != '/') {
      return false;
    }
    return child.find('/', 1U) == std::string::npos;
  }
  if (child.size() <= parent.size() + 1U || child.compare(0, parent.size(), parent) != 0 ||
      child[parent.size()] != '/') {
    return false;
  }
  return child.find('/', parent.size() + 1U) == std::string::npos;
}

bool ParseViteCacheProvenance(napi_env env, napi_value value, ViteCacheProvenanceNative* output) {
  napi_value provenance;
  napi_value version;
  napi_value install_id;
  napi_value parent_path;
  napi_value root;
  napi_value parent;
  napi_value parent_identity;
  napi_value inverse;
  napi_value inverse_kind;
  napi_value inverse_root;
  napi_value inverse_parent;
  napi_value inverse_path;
  uint32_t parsed_version = 0;
  std::string inverse_kind_value;
  std::string inverse_path_value;
  Identity inverse_root_identity{};
  Identity inverse_parent_identity{};
  if (!GetObject(env, value, &provenance) ||
      !GetRequiredProperty(env, provenance, "version", &version) ||
      !GetUint32(env, version, UINT32_MAX, &parsed_version) || parsed_version != 1U ||
      !GetRequiredProperty(env, provenance, "installId", &install_id) ||
      !GetString(env, install_id, &output->install_id, 128U) ||
      !IsViteCacheInstallId(output->install_id) ||
      !GetRequiredProperty(env, provenance, "canonicalParentPath", &parent_path) ||
      !ParseCanonicalAbsolutePath(env, parent_path, &output->canonical_parent_path) ||
      !GetRequiredProperty(env, provenance, "root", &root) ||
      !ParseViteCacheRecord(env, root, &output->root) ||
      !GetRequiredProperty(env, provenance, "parent", &parent) ||
      !ParseViteCacheRecord(env, parent, &output->parent) ||
      !GetRequiredProperty(env, provenance, "parentIdentity", &parent_identity) ||
      !ParseIdentity(env, parent_identity, &output->parent_identity) ||
      !GetRequiredProperty(env, provenance, "inverse", &inverse) || !GetObject(env, inverse, &inverse) ||
      !GetRequiredProperty(env, inverse, "kind", &inverse_kind) ||
      !GetString(env, inverse_kind, &inverse_kind_value, 32U) ||
      !GetRequiredProperty(env, inverse, "rootIdentity", &inverse_root) ||
      !ParseIdentity(env, inverse_root, &inverse_root_identity) ||
      !GetRequiredProperty(env, inverse, "parentIdentity", &inverse_parent) ||
      !ParseIdentity(env, inverse_parent, &inverse_parent_identity) ||
      !GetRequiredProperty(env, inverse, "canonicalPath", &inverse_path) ||
      !ParseCanonicalAbsolutePath(env, inverse_path, &inverse_path_value)) {
    return false;
  }
  if (output->root.identity.device != output->parent.identity.device ||
      !SameIdentity(output->parent.identity, output->parent_identity) ||
      inverse_kind_value != "remove-created-vite-cache" ||
      inverse_path_value != output->root.canonical_path ||
      !SameIdentity(inverse_root_identity, output->root.identity) ||
      !SameIdentity(inverse_parent_identity, output->parent_identity) ||
      output->parent.canonical_path != output->canonical_parent_path ||
      !IsCanonicalChildPath(output->canonical_parent_path, output->root.canonical_path) ||
      SameIdentity(output->root.identity, output->parent.identity) ||
      output->root.uid != static_cast<uint32_t>(geteuid()) ||
      output->parent.uid != static_cast<uint32_t>(geteuid()) ||
      output->root.uid != output->parent.uid || output->root.gid != output->parent.gid) {
    ThrowCacheDenied(env);
    return false;
  }
  return true;
}

bool ParseViteCacheLimits(napi_env env, napi_value value, ViteCacheLimitsNative* output) {
  napi_value limits;
  if (!GetObject(env, value, &limits) ||
      !GetRequiredUint32(env, limits, "maxEntries", kMaximumViteCacheEntries, &output->max_entries) ||
      !GetRequiredUint32(env, limits, "maxFiles", kMaximumViteCacheFiles, &output->max_files) ||
      !GetRequiredUint32(env, limits, "maxBytes", kMaximumViteCacheBytes, &output->max_bytes) ||
      !GetRequiredUint32(env, limits, "maxDepth", kMaximumViteCacheDepth, &output->max_depth) ||
      output->max_entries == 0U || output->max_files == 0U || output->max_bytes == 0U) {
    if (output->max_entries == 0U || output->max_files == 0U || output->max_bytes == 0U) {
      ThrowCacheDenied(env);
    }
    return false;
  }
  return true;
}

bool SplitCanonicalPath(const std::string& path, std::vector<std::string>* output) {
  if (output == nullptr || path.empty() || path.size() > kMaximumPathBytes || path[0] != '/' ||
      (path.size() > 1U && path.back() == '/')) {
    return false;
  }
  if (path == "/") {
    return true;
  }
  size_t begin = 1U;
  while (begin < path.size()) {
    const size_t end = path.find('/', begin);
    const size_t length = (end == std::string::npos ? path.size() : end) - begin;
    if (length == 0U || length > kMaximumPathComponentBytes ||
        output->size() >= kMaximumPathComponents) {
      return false;
    }
    const std::string component = path.substr(begin, length);
    if (component == "." || component == ".." || component.find('\0') != std::string::npos) {
      return false;
    }
    output->push_back(component);
    if (end == std::string::npos) {
      return true;
    }
    begin = end + 1U;
  }
  return false;
}

bool SameStatIdentity(const struct stat& stat, const Identity& identity) {
  return static_cast<uint64_t>(stat.st_dev) == identity.device &&
         static_cast<uint64_t>(stat.st_ino) == identity.inode;
}

bool MatchesViteCacheRecord(const struct stat& stat, const ViteCacheRecord& record) {
  const uid_t effective_uid = geteuid();
  return S_ISDIR(stat.st_mode) && SameStatIdentity(stat, record.identity) &&
         record.uid == effective_uid && stat.st_uid == effective_uid && stat.st_uid == record.uid &&
         stat.st_gid == record.gid && static_cast<mode_t>(stat.st_mode & 07777) == record.mode;
}

int OpenDirectoryNameAt(int parent_fd, const char* name) {
  return openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int OpenViteCacheDirectoryDescriptor(int directory_fd) {
  return openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

bool OpenViteCacheAuthority(const ViteCacheProvenanceNative& provenance, FileDescriptor* parent_fd,
                            FileDescriptor* root_fd) {
  std::vector<std::string> parent_components;
  std::vector<std::string> root_components;
  if (!SplitCanonicalPath(provenance.canonical_parent_path, &parent_components) ||
      !SplitCanonicalPath(provenance.root.canonical_path, &root_components) ||
      root_components.size() != parent_components.size() + 1U ||
      !std::equal(parent_components.begin(), parent_components.end(), root_components.begin())) {
    return false;
  }

  FileDescriptor current(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  if (current.Get() < 0) {
    return false;
  }
  for (const std::string& component : parent_components) {
    FileDescriptor next(OpenDirectoryAt(current.Get(), component));
    if (next.Get() < 0) {
      return false;
    }
    current = std::move(next);
  }

  struct stat parent_stat{};
  if (fstat(current.Get(), &parent_stat) != 0 ||
      !MatchesViteCacheRecord(parent_stat, provenance.parent) || !HasSafeAcl(current.Get())) {
    return false;
  }

  const std::string& leaf = root_components.back();
  struct stat entry_stat{};
  if (fstatat(current.Get(), leaf.c_str(), &entry_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !MatchesViteCacheRecord(entry_stat, provenance.root)) {
    return false;
  }
  FileDescriptor root(OpenDirectoryAt(current.Get(), leaf));
  struct stat root_stat{};
  if (root.Get() < 0 || fstat(root.Get(), &root_stat) != 0 ||
      !MatchesViteCacheRecord(root_stat, provenance.root) || !HasSafeAcl(root.Get()) ||
      !SameStatIdentity(entry_stat, provenance.root.identity) ||
      root_stat.st_dev != parent_stat.st_dev) {
    return false;
  }

  struct stat linked_entry_stat{};
  if (fstatat(current.Get(), leaf.c_str(), &linked_entry_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
      !MatchesViteCacheRecord(linked_entry_stat, provenance.root)) {
    return false;
  }

  *parent_fd = std::move(current);
  *root_fd = std::move(root);
  return true;
}

bool ValidateViteCacheSessionAuthority(ViteCacheSession* session) {
  if (session == nullptr || session->closed || session->parent_fd.Get() < 0 ||
      session->root_fd.Get() < 0) {
    return false;
  }
  struct stat retained_parent{};
  struct stat retained_root{};
  if (fstat(session->parent_fd.Get(), &retained_parent) != 0 ||
      fstat(session->root_fd.Get(), &retained_root) != 0 ||
      !MatchesViteCacheRecord(retained_parent, session->provenance.parent) ||
      !MatchesViteCacheRecord(retained_root, session->provenance.root) ||
      !HasSafeAcl(session->parent_fd.Get()) || !HasSafeAcl(session->root_fd.Get()) ||
      retained_parent.st_dev != retained_root.st_dev) {
    return false;
  }

  std::vector<std::string> root_components;
  if (!SplitCanonicalPath(session->provenance.root.canonical_path, &root_components) ||
      root_components.empty()) {
    return false;
  }
  struct stat linked_root{};
  if (fstatat(session->parent_fd.Get(), root_components.back().c_str(), &linked_root,
              AT_SYMLINK_NOFOLLOW) != 0 ||
      !MatchesViteCacheRecord(linked_root, session->provenance.root)) {
    return false;
  }

  FileDescriptor reopened_parent;
  FileDescriptor reopened_root;
  if (!OpenViteCacheAuthority(session->provenance, &reopened_parent, &reopened_root)) {
    return false;
  }
  return true;
}

bool UnwrapViteCacheSession(napi_env env, napi_value value, ViteCacheSession** output) {
  bool is_tagged = false;
  if (!GetObject(env, value, &value) ||
      !IsNapiStatusOk(napi_check_object_type_tag(env, value, &kViteCacheSessionTypeTag, &is_tagged)) ||
      !is_tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowCacheDenied(env);
    return false;
  }
  return true;
}

bool RequireViteCacheSession(napi_env env, napi_value value, ViteCacheSession** output) {
  if (!UnwrapViteCacheSession(env, value, output)) {
    return false;
  }
  if (!ValidateViteCacheSessionAuthority(*output)) {
    ThrowCacheDenied(env);
    return false;
  }
  return true;
}

bool CheckViteCacheEntryBudget(ViteCacheTreeResult* result, const ViteCacheLimitsNative& limits) {
  if (result->entries.size() >= limits.max_entries) {
    return false;
  }
  return true;
}

ViteCacheEntryKind ClassifyViteCacheEntry(const struct stat& stat) {
  if (S_ISDIR(stat.st_mode)) {
    return kViteCacheDirectory;
  }
  if (S_ISREG(stat.st_mode)) {
    return kViteCacheRegularFile;
  }
  if (S_ISLNK(stat.st_mode)) {
    return kViteCacheSymlink;
  }
  if (S_ISSOCK(stat.st_mode)) {
    return kViteCacheSocket;
  }
  if (S_ISFIFO(stat.st_mode)) {
    return kViteCacheFifo;
  }
  if (S_ISBLK(stat.st_mode)) {
    return kViteCacheBlockDevice;
  }
  if (S_ISCHR(stat.st_mode)) {
    return kViteCacheCharacterDevice;
  }
  return kViteCacheUnknown;
}

void ReadTimes(const struct stat& stat, ViteCacheTreeEntry* entry) {
#if defined(__APPLE__)
  entry->modified_seconds = stat.st_mtimespec.tv_sec;
  entry->modified_nanoseconds = stat.st_mtimespec.tv_nsec;
  entry->changed_seconds = stat.st_ctimespec.tv_sec;
  entry->changed_nanoseconds = stat.st_ctimespec.tv_nsec;
#else
  entry->modified_seconds = stat.st_mtim.tv_sec;
  entry->modified_nanoseconds = stat.st_mtim.tv_nsec;
  entry->changed_seconds = stat.st_ctim.tv_sec;
  entry->changed_nanoseconds = stat.st_ctim.tv_nsec;
#endif
}

bool AppendViteCacheTreeEntry(const struct stat& stat, const Identity* parent_identity, uint32_t depth,
                              ViteCacheTreeResult* result, const ViteCacheLimitsNative& limits) {
  if (!CheckViteCacheEntryBudget(result, limits) || stat.st_size < 0) {
    return false;
  }
  const ViteCacheEntryKind kind = ClassifyViteCacheEntry(stat);
  if (kind == kViteCacheRegularFile) {
    if (result->file_count >= limits.max_files ||
        static_cast<uint64_t>(stat.st_size) > limits.max_bytes - result->aggregate_bytes) {
      return false;
    }
    result->file_count += 1U;
    result->aggregate_bytes += static_cast<uint64_t>(stat.st_size);
  }
  ViteCacheTreeEntry entry{
      .identity = {static_cast<uint64_t>(stat.st_dev), static_cast<uint64_t>(stat.st_ino)},
      .parent_identity = parent_identity == nullptr ? Identity{} : *parent_identity,
      .has_parent_identity = parent_identity != nullptr,
      .device = static_cast<uint64_t>(stat.st_dev),
      .uid = stat.st_uid,
      .gid = stat.st_gid,
      .mode = static_cast<mode_t>(stat.st_mode & 07777),
      .size_bytes = kind == kViteCacheRegularFile ? static_cast<uint64_t>(stat.st_size) : 0U,
      .link_count = static_cast<uint64_t>(stat.st_nlink),
      .depth = depth,
      .kind = kind,
  };
  ReadTimes(stat, &entry);
  result->entries.push_back(entry);
  return true;
}
bool CaptureSafeViteCacheDirectoryState(int fd, const ViteCacheSession* session,
                                        struct stat* output);
bool RevalidateSafeViteCacheDirectoryState(int fd, const struct stat& before,
                                           const ViteCacheSession* session);

bool RevalidateViteCacheChildLink(int parent_fd, const char* name,
                                  const struct stat& expected_child) {
  struct stat linked_child{};
  return fstatat(parent_fd, name, &linked_child, AT_SYMLINK_NOFOLLOW) == 0 &&
         S_ISDIR(linked_child.st_mode) &&
         SameStatIdentity(linked_child,
                          Identity{static_cast<uint64_t>(expected_child.st_dev),
                                   static_cast<uint64_t>(expected_child.st_ino)});
}

bool TraverseViteCacheTree(int directory_fd, const Identity& parent_identity, uint32_t depth,
                           uint64_t root_device, const ViteCacheSession* session,
                           const struct stat& directory_before, ViteCacheTreeResult* result,
                           const ViteCacheLimitsNative& limits) {

  const int duplicated_fd = OpenViteCacheDirectoryDescriptor(directory_fd);
  if (duplicated_fd < 0) {
    return false;
  }
  DIR* directory = fdopendir(duplicated_fd);
  if (directory == nullptr) {
    (void)close(duplicated_fd);
    return false;
  }

  bool valid = true;
  errno = 0;
  while (valid) {
    errno = 0;
    struct dirent* entry = readdir(directory);
    if (entry == nullptr) {
      if (errno != 0) {
        valid = false;
      }
      break;
    }
    if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    if (depth >= limits.max_depth) {
      valid = false;
      break;
    }

    struct stat child_stat{};
    if (fstatat(directory_fd, entry->d_name, &child_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
        static_cast<uint64_t>(child_stat.st_dev) != root_device) {
      valid = false;
      break;
    }

    if (S_ISDIR(child_stat.st_mode)) {
      FileDescriptor child_fd(OpenDirectoryNameAt(directory_fd, entry->d_name));
      struct stat child_before{};
      if (child_fd.Get() < 0 ||
          !CaptureSafeViteCacheDirectoryState(child_fd.Get(), session, &child_before) ||
          !SameStatIdentity(child_before,
                            Identity{static_cast<uint64_t>(child_stat.st_dev),
                                     static_cast<uint64_t>(child_stat.st_ino)}) ||
          !AppendViteCacheTreeEntry(child_before, &parent_identity, depth + 1U, result, limits) ||
          !TraverseViteCacheTree(child_fd.Get(),
                                 Identity{static_cast<uint64_t>(child_before.st_dev),
                                          static_cast<uint64_t>(child_before.st_ino)},
                                 depth + 1U, root_device, session, child_before, result, limits) ||
          !RevalidateViteCacheChildLink(directory_fd, entry->d_name, child_before)) {
        valid = false;
        break;
      }
    } else if (!AppendViteCacheTreeEntry(child_stat, &parent_identity, depth + 1U, result,
                                          limits)) {
      valid = false;
      break;
    }
  }

  if (closedir(directory) != 0) {
    valid = false;
  }
  return valid &&
         RevalidateSafeViteCacheDirectoryState(directory_fd, directory_before, session);
}
bool ValidateViteCacheTreeBudgets(const ViteCacheTreeResult& tree,
                                  const ViteCacheLimitsNative& limits) {
  if (tree.entries.empty() || tree.entries.size() > limits.max_entries) {
    return false;
  }

  uint32_t files = 0U;
  uint64_t aggregate_bytes = 0U;
  for (const ViteCacheTreeEntry& entry : tree.entries) {
    if (entry.depth > limits.max_depth) {
      return false;
    }
    if (entry.kind != kViteCacheRegularFile) {
      continue;
    }
    if (files >= limits.max_files || entry.size_bytes > limits.max_bytes - aggregate_bytes) {
      return false;
    }
    files += 1U;
    aggregate_bytes += entry.size_bytes;
  }
  return files == tree.file_count && aggregate_bytes == tree.aggregate_bytes;
}


bool ScanViteCacheTreeInternal(ViteCacheSession* session, const ViteCacheLimitsNative& limits,
                               ViteCacheTreeResult* output) {
  if (!ValidateViteCacheSessionAuthority(session)) {
    return false;
  }
  struct stat root_before{};
  if (!CaptureSafeViteCacheDirectoryState(session->root_fd.Get(), session, &root_before) ||
      !MatchesViteCacheRecord(root_before, session->provenance.root)) {
    return false;
  }

  output->entries.clear();
  output->file_count = 0;
  output->aggregate_bytes = 0;
  output->entries.reserve(limits.max_entries);
  if (!AppendViteCacheTreeEntry(root_before, &session->provenance.parent_identity, 0U, output,
                                limits) ||
      !TraverseViteCacheTree(session->root_fd.Get(), session->provenance.root.identity, 0U,
                             static_cast<uint64_t>(root_before.st_dev), session, root_before,
                             output, limits) ||
      !ValidateViteCacheTreeBudgets(*output, limits) ||
      !ValidateViteCacheSessionAuthority(session)) {
    return false;
  }
  return true;
}
bool CreateUnsignedSafe(napi_env env, uint64_t value, napi_value* output) {
  return value <= kMaximumSafeJavaScriptInteger &&
         IsNapiStatusOk(napi_create_double(env, static_cast<double>(value), output));
}

bool CreateViteCacheIdentity(napi_env env, const Identity& identity, napi_value* output) {
  napi_value result;
  napi_value device;
  napi_value inode;
  const std::string device_value = std::to_string(identity.device);
  const std::string inode_value = std::to_string(identity.inode);
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, device_value.c_str(), device_value.size(), &device)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, inode_value.c_str(), inode_value.size(), &inode)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "device", device)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "inode", inode))) {
    return false;
  }
  *output = result;
  return true;
}

bool CreateViteCacheOwner(napi_env env, uid_t uid, gid_t gid, napi_value* output) {
  napi_value result;
  napi_value uid_value;
  napi_value gid_value;
  if (!CreateUnsignedSafe(env, static_cast<uint64_t>(uid), &uid_value) ||
      !CreateUnsignedSafe(env, static_cast<uint64_t>(gid), &gid_value) ||
      !IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "uid", uid_value)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "gid", gid_value))) {
    return false;
  }
  *output = result;
  return true;
}

bool CreateViteCacheRecord(napi_env env, const ViteCacheRecord& record, napi_value* output) {
  napi_value result;
  napi_value identity;
  napi_value canonical_path;
  napi_value device;
  napi_value owner;
  napi_value mode;
  const std::string device_value = std::to_string(record.identity.device);
  if (!CreateViteCacheIdentity(env, record.identity, &identity) ||
      !CreateViteCacheOwner(env, record.uid, record.gid, &owner) ||
      !IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, record.canonical_path.c_str(),
                                               record.canonical_path.size(), &canonical_path)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, device_value.c_str(), device_value.size(), &device)) ||
      !IsNapiStatusOk(napi_create_uint32(env, static_cast<uint32_t>(record.mode), &mode)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "identity", identity)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "canonicalPath", canonical_path)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "device", device)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "owner", owner)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "mode", mode))) {
    return false;
  }
  *output = result;
  return true;
}

const char* ViteCacheKindName(int kind) {
  switch (kind) {
    case kViteCacheDirectory:
      return "directory";
    case kViteCacheRegularFile:
      return "regular-file";
    case kViteCacheSymlink:
      return "symlink";
    case kViteCacheSocket:
      return "socket";
    case kViteCacheFifo:
      return "fifo";
    case kViteCacheBlockDevice:
      return "block-device";
    case kViteCacheCharacterDevice:
      return "character-device";
    default:
      return "unknown";
  }
}

bool CreateViteCacheTreeEntry(napi_env env, const ViteCacheTreeEntry& entry, napi_value* output) {
  napi_value result;
  napi_value identity;
  napi_value parent_identity;
  napi_value device;
  napi_value owner;
  napi_value mode;
  napi_value kind;
  napi_value depth;
  napi_value size_bytes;
  napi_value link_count;
  napi_value escaped;
  const std::string device_value = std::to_string(entry.device);
  const char* kind_name = ViteCacheKindName(entry.kind);
  if (!CreateViteCacheIdentity(env, entry.identity, &identity) ||
      (entry.has_parent_identity && !CreateViteCacheIdentity(env, entry.parent_identity, &parent_identity)) ||
      (!entry.has_parent_identity && !IsNapiStatusOk(napi_get_null(env, &parent_identity))) ||
      !CreateViteCacheOwner(env, entry.uid, entry.gid, &owner) ||
      !CreateUnsignedSafe(env, entry.size_bytes, &size_bytes) ||
      !CreateUnsignedSafe(env, entry.link_count, &link_count) ||
      !IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, device_value.c_str(), device_value.size(), &device)) ||
      !IsNapiStatusOk(napi_create_uint32(env, static_cast<uint32_t>(entry.mode), &mode)) ||
      !IsNapiStatusOk(napi_create_string_utf8(env, kind_name, NAPI_AUTO_LENGTH, &kind)) ||
      !IsNapiStatusOk(napi_create_uint32(env, entry.depth, &depth)) ||
      !IsNapiStatusOk(napi_get_boolean(env, false, &escaped)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "identity", identity)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "parentIdentity", parent_identity)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "device", device)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "owner", owner)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "mode", mode)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "kind", kind)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "depth", depth)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "sizeBytes", size_bytes)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "linkCount", link_count)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "escaped", escaped))) {
    return false;
  }
  *output = result;
  return true;
}

bool CreateViteCacheTreeResult(napi_env env, const ViteCacheSession* session,
                               const ViteCacheTreeResult& tree, napi_value* output) {
  napi_value result;
  napi_value root_identity;
  napi_value entries;
  if (!CreateViteCacheIdentity(env, session->provenance.root.identity, &root_identity) ||
      !IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_array_with_length(env, tree.entries.size(), &entries))) {
    return false;
  }
  for (uint32_t index = 0; index < tree.entries.size(); ++index) {
    napi_value entry;
    if (!CreateViteCacheTreeEntry(env, tree.entries[index], &entry) ||
        !IsNapiStatusOk(napi_set_element(env, entries, index, entry))) {
      return false;
    }
  }
  if (!IsNapiStatusOk(napi_set_named_property(env, result, "rootIdentity", root_identity)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "entries", entries))) {
    return false;
  }
  *output = result;
  return true;
}
bool IsSafeViteCacheTreeEntry(const ViteCacheTreeEntry& entry, const ViteCacheSession* session) {
  if (entry.device != session->provenance.root.identity.device ||
      entry.uid != static_cast<uid_t>(geteuid()) ||
      entry.uid != session->provenance.root.uid || entry.gid != session->provenance.root.gid) {
    return false;
  }
  if (entry.kind == kViteCacheDirectory) {
    return entry.mode == 0700U;
  }
  return entry.kind == kViteCacheRegularFile && entry.link_count == 1U && entry.mode == 0600U;
}

bool IsSafeViteCacheDirectory(const struct stat& stat, const ViteCacheSession* session) {
  return S_ISDIR(stat.st_mode) &&
         static_cast<uint64_t>(stat.st_dev) == session->provenance.root.identity.device &&
         stat.st_uid == geteuid() && stat.st_uid == session->provenance.root.uid &&
         stat.st_gid == session->provenance.root.gid &&
         static_cast<mode_t>(stat.st_mode & 07777) == 0700U;
}

bool IsSafeViteCacheFile(const struct stat& stat, const ViteCacheSession* session) {
  return S_ISREG(stat.st_mode) && stat.st_nlink == 1 && stat.st_size >= 0 &&
         static_cast<uint64_t>(stat.st_dev) == session->provenance.root.identity.device &&
         stat.st_uid == geteuid() && stat.st_uid == session->provenance.root.uid &&
         stat.st_gid == session->provenance.root.gid &&
         static_cast<mode_t>(stat.st_mode & 07777) == 0600U;
}

bool SameViteCacheFileState(const struct stat& before, const struct stat& after) {
  return SameFileState(before, after) && before.st_gid == after.st_gid;
}

bool CaptureSafeViteCacheDirectoryState(int fd, const ViteCacheSession* session,
                                        struct stat* output) {
  struct stat state{};
  if (fstat(fd, &state) != 0 || !IsSafeViteCacheDirectory(state, session) || !HasSafeAcl(fd)) {
    return false;
  }
  *output = state;
  return true;
}

bool RevalidateSafeViteCacheDirectoryState(int fd, const struct stat& before,
                                           const ViteCacheSession* session) {
  struct stat after{};
  return fstat(fd, &after) == 0 && IsSafeViteCacheDirectory(after, session) &&
         HasSafeAcl(fd) && SameViteCacheFileState(before, after);
}

constexpr size_t kSha256BlockBytes = 64U;
constexpr size_t kSha256DigestBytes = 32U;

bool IsBase64UrlByte(unsigned char byte) {
  return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
         (byte >= '0' && byte <= '9') || byte == '-' || byte == '_';
}

bool IsLowercaseHexByte(unsigned char byte) {
  return (byte >= 'a' && byte <= 'f') || (byte >= '0' && byte <= '9');
}

unsigned char Base64UrlValue(unsigned char byte) {
  if (byte >= 'A' && byte <= 'Z') {
    return static_cast<unsigned char>(byte - 'A');
  }
  if (byte >= 'a' && byte <= 'z') {
    return static_cast<unsigned char>(byte - 'a' + 26U);
  }
  if (byte >= '0' && byte <= '9') {
    return static_cast<unsigned char>(byte - '0' + 52U);
  }
  return byte == '-' ? 62U : 63U;
}

bool IsCanonicalBase64UrlToken(
    const std::array<unsigned char, kMaximumViteCacheCredentialBytes>& candidate, size_t length) {
  const size_t remainder = length % 4U;
  if (remainder == 1U) {
    return false;
  }

  size_t decoded_length = (length / 4U) * 3U;
  if (remainder == 2U) {
    decoded_length += 1U;
  } else if (remainder == 3U) {
    decoded_length += 2U;
  }
  if (decoded_length < 32U) {
    return false;
  }
  if (remainder == 0U) {
    return true;
  }

  const unsigned char trailing_sextet = Base64UrlValue(candidate[length - 1U]);
  return remainder == 2U ? (trailing_sextet & 0x0FU) == 0U
                         : (trailing_sextet & 0x03U) == 0U;
}

class Sha256 final {
 public:
  Sha256()
      : state_{0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
               0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U} {}

  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  ~Sha256() { Clear(); }

  bool Update(const unsigned char* data, size_t length) {
    if ((data == nullptr && length != 0U) ||
        length > static_cast<size_t>(UINT64_MAX - total_bytes_)) {
      return false;
    }

    total_bytes_ += static_cast<uint64_t>(length);
    while (length > 0U) {
      block_[block_length_] = *data;
      block_length_ += 1U;
      data += 1U;
      length -= 1U;
      if (block_length_ == block_.size()) {
        Transform();
        block_length_ = 0U;
      }
    }
    return true;
  }

  bool Final(std::array<unsigned char, kSha256DigestBytes>* output) {
    if (output == nullptr || total_bytes_ > UINT64_MAX / 8U) {
      return false;
    }

    const uint64_t bit_length = total_bytes_ * 8U;
    block_[block_length_] = 0x80U;
    block_length_ += 1U;
    if (block_length_ > 56U) {
      ZeroizeMemory(block_.data() + block_length_, block_.size() - block_length_);
      Transform();
      block_length_ = 0U;
    }
    ZeroizeMemory(block_.data() + block_length_, 56U - block_length_);
    block_length_ = 56U;
    for (size_t index = 0; index < 8U; ++index) {
      block_[block_length_ + index] =
          static_cast<unsigned char>(bit_length >> ((7U - index) * 8U));
    }
    Transform();
    block_length_ = 0U;

    for (size_t index = 0; index < state_.size(); ++index) {
      (*output)[index * 4U] = static_cast<unsigned char>(state_[index] >> 24U);
      (*output)[index * 4U + 1U] = static_cast<unsigned char>(state_[index] >> 16U);
      (*output)[index * 4U + 2U] = static_cast<unsigned char>(state_[index] >> 8U);
      (*output)[index * 4U + 3U] = static_cast<unsigned char>(state_[index]);
    }

    Clear();
    return true;
  }

 private:
  static uint32_t RotateRight(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32U - count));
  }

  void Transform() {
    std::array<uint32_t, 64U> words{};
    for (size_t index = 0; index < 16U; ++index) {
      words[index] = (static_cast<uint32_t>(block_[index * 4U]) << 24U) |
                     (static_cast<uint32_t>(block_[index * 4U + 1U]) << 16U) |
                     (static_cast<uint32_t>(block_[index * 4U + 2U]) << 8U) |
                     static_cast<uint32_t>(block_[index * 4U + 3U]);
    }
    for (size_t index = 16U; index < words.size(); ++index) {
      const uint32_t sigma0 = RotateRight(words[index - 15U], 7U) ^
                              RotateRight(words[index - 15U], 18U) ^
                              (words[index - 15U] >> 3U);
      const uint32_t sigma1 = RotateRight(words[index - 2U], 17U) ^
                              RotateRight(words[index - 2U], 19U) ^
                              (words[index - 2U] >> 10U);
      words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
    }

    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];
    for (size_t index = 0; index < words.size(); ++index) {
      const uint32_t sigma1 = RotateRight(e, 6U) ^ RotateRight(e, 11U) ^ RotateRight(e, 25U);
      const uint32_t choose = (e & f) ^ (~e & g);
      const uint32_t temporary1 = h + sigma1 + choose + kRoundConstants[index] + words[index];
      const uint32_t sigma0 = RotateRight(a, 2U) ^ RotateRight(a, 13U) ^ RotateRight(a, 22U);
      const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temporary2 = sigma0 + majority;

      h = g;
      g = f;
      f = e;
      e = d + temporary1;
      d = c;
      c = b;
      b = a;
      a = temporary1 + temporary2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
    ZeroizeMemory(words.data(), words.size() * sizeof(words[0]));
  }

  void Clear() {
    ZeroizeMemory(state_.data(), state_.size() * sizeof(state_[0]));
    ZeroizeMemory(block_.data(), block_.size());
    total_bytes_ = 0U;
    block_length_ = 0U;
  }

  static constexpr std::array<uint32_t, 64U> kRoundConstants = {
      0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U,
      0x923F82A4U, 0xAB1C5ED5U, 0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
      0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U, 0xE49B69C1U, 0xEFBE4786U,
      0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
      0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U, 0xC6E00BF3U, 0xD5A79147U,
      0x06CA6351U, 0x14292967U, 0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
      0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U, 0xA2BFE8A1U, 0xA81A664BU,
      0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
      0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU,
      0x5B9CCA4FU, 0x682E6FF3U, 0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
      0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U};

  std::array<uint32_t, 8U> state_{};
  std::array<unsigned char, kSha256BlockBytes> block_{};
  uint64_t total_bytes_ = 0U;
  size_t block_length_ = 0U;
};
std::string Sha256Digest(const SensitiveBytes& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  Sha256 hash;
  std::array<unsigned char, kSha256DigestBytes> digest{};
  if (!hash.Update(bytes.Data(), bytes.Size()) || !hash.Final(&digest)) {
    return {};
  }
  std::string encoded("sha256:");
  encoded.reserve(71U);
  for (const unsigned char value : digest) {
    encoded.push_back(kHex[value >> 4U]);
    encoded.push_back(kHex[value & 0x0FU]);
  }
  return encoded;
}

bool MatchesViteCacheTokenHash(const ViteCacheTokenHashes& token_hashes,
                               const ViteCacheTokenHash& candidate, bool* matched,
                               uint64_t* work_units) {
  if (matched == nullptr) {
    return false;
  }
  if (work_units != nullptr) {
    if (token_hashes.values.size() >
        kMaximumViteCacheMatcherWorkUnits -
            std::min(*work_units, kMaximumViteCacheMatcherWorkUnits)) {
      return false;
    }
    *work_units += token_hashes.values.size();
  }

  unsigned char match = 0U;
  for (const ViteCacheTokenHash& token_hash : token_hashes.values) {
    unsigned char difference = 0U;
    for (size_t index = 0; index < candidate.size(); ++index) {
      difference |= static_cast<unsigned char>(candidate[index] ^ token_hash[index]);
    }
    match |= static_cast<unsigned char>(difference == 0U);
  }
  *matched = match != 0U;
  return true;
}

struct ViteCacheTokenMatcher {
  explicit ViteCacheTokenMatcher(const ViteCacheTokenHashes& token_hashes)
      : token_hashes(token_hashes) {}

  ViteCacheTokenMatcher(const ViteCacheTokenMatcher&) = delete;
  ViteCacheTokenMatcher& operator=(const ViteCacheTokenMatcher&) = delete;

  ~ViteCacheTokenMatcher() {
    ZeroizeMemory(candidate.data(), candidate.size());
    ZeroizeMemory(literal_candidate.data(), literal_candidate.size());
    run_length = 0U;
    literal_run_length = 0U;
    work_units = 0U;
  }

  bool Consume(unsigned char byte) {
    if (!IsBase64UrlByte(byte)) {
      return FinishRun();
    }
    if (run_length == candidate.size()) {
      ZeroizeMemory(candidate.data(), run_length);
      run_length = 0U;
      FinishLiteralRun();
      return false;
    }
    if (IsLowercaseHexByte(byte)) {
      if (literal_run_length < literal_candidate.size()) {
        literal_candidate[literal_run_length] = byte;
      }
      literal_run_length += 1U;
    } else if (!FinishLiteralRun()) {
      return false;
    }
    candidate[run_length] = byte;
    run_length += 1U;
    return true;
  }

  bool Finish() { return FinishRun(); }

  const ViteCacheTokenHashes& token_hashes;
  std::array<unsigned char, kMaximumViteCacheCredentialBytes> candidate{};
  ViteCacheTokenHash literal_candidate{};
  size_t run_length = 0U;
  size_t literal_run_length = 0U;
  uint64_t work_units = 0U;
  bool detected = false;

 private:
  bool MatchCandidate(const ViteCacheTokenHash& candidate_hash) {
    bool matched = false;
    if (!MatchesViteCacheTokenHash(token_hashes, candidate_hash, &matched, &work_units)) {
      return false;
    }
    detected = matched || detected;
    return true;
  }

  bool FinishBase64Run() {
    std::array<unsigned char, kSha256DigestBytes> digest{};
    ViteCacheTokenHash digest_hex{};
    bool valid = true;
    if (run_length != 0U && IsCanonicalBase64UrlToken(candidate, run_length)) {
      Sha256 hash;
      valid = hash.Update(candidate.data(), run_length) && hash.Final(&digest);
      if (valid) {
        constexpr char kHex[] = "0123456789abcdef";
        for (size_t index = 0; index < digest.size(); ++index) {
          digest_hex[index * 2U] = static_cast<unsigned char>(kHex[digest[index] >> 4U]);
          digest_hex[index * 2U + 1U] =
              static_cast<unsigned char>(kHex[digest[index] & 0x0FU]);
        }
        valid = MatchCandidate(digest_hex);
      }
    }

    ZeroizeMemory(digest.data(), digest.size());
    ZeroizeMemory(digest_hex.data(), digest_hex.size());
    ZeroizeMemory(candidate.data(), run_length);
    run_length = 0U;
    return valid;
  }

  bool FinishLiteralRun() {
    bool valid = true;
    if (literal_run_length == literal_candidate.size()) {
      valid = MatchCandidate(literal_candidate);
    }
    ZeroizeMemory(literal_candidate.data(), literal_candidate.size());
    literal_run_length = 0U;
    return valid;
  }

  bool FinishRun() {
    const bool base64_valid = FinishBase64Run();
    const bool literal_valid = FinishLiteralRun();
    return base64_valid && literal_valid;
  }
};

bool ScanViteCacheCanaryFile(int parent_fd, const char* name, const struct stat& listed_stat,
                              ViteCacheSession* session, ViteCacheTokenMatcher* matcher) {
  FileDescriptor file_fd(openat(parent_fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
  struct stat before{};
  if (file_fd.Get() < 0 || fstat(file_fd.Get(), &before) != 0 ||
      !IsSafeViteCacheFile(before, session) || !HasSafeAcl(file_fd.Get()) ||
      !SameStatIdentity(before, Identity{static_cast<uint64_t>(listed_stat.st_dev),
                                         static_cast<uint64_t>(listed_stat.st_ino)})) {
    return false;
  }

  std::array<unsigned char, 64U * 1024U> buffer{};
  size_t offset = 0;
  const size_t size = static_cast<size_t>(before.st_size);
  bool valid = true;
  while (valid && offset < size) {
    const size_t requested = std::min(buffer.size(), size - offset);
    const ssize_t read_count = pread(file_fd.Get(), buffer.data(), requested, static_cast<off_t>(offset));
    if (read_count < 0 && errno == EINTR) {
      continue;
    }
    if (read_count <= 0) {
      valid = false;
      break;
    }
    for (ssize_t index = 0; index < read_count; ++index) {
      if (!matcher->Consume(buffer[static_cast<size_t>(index)])) {
        valid = false;
        break;
      }
    }
    offset += static_cast<size_t>(read_count);
  }
  if (valid && !matcher->Finish()) {
    valid = false;
  }
  ZeroizeMemory(buffer.data(), buffer.size());
  if (!valid) {
    return false;
  }

  struct stat after{};
  return fstat(file_fd.Get(), &after) == 0 && IsSafeViteCacheFile(after, session) &&
         HasSafeAcl(file_fd.Get()) && SameViteCacheFileState(before, after);
}

bool ScanViteCacheCanaryDirectory(int directory_fd, uint32_t depth, ViteCacheSession* session,
                                  const ViteCacheLimitsNative& limits, uint32_t* entries,
                                  uint32_t* files, uint64_t* aggregate_bytes,
                                  ViteCacheTokenMatcher* matcher) {
  struct stat before{};
  if (!CaptureSafeViteCacheDirectoryState(directory_fd, session, &before)) {
    return false;
  }
  const int duplicated_fd = OpenViteCacheDirectoryDescriptor(directory_fd);
  if (duplicated_fd < 0) {
    return false;
  }
  DIR* directory = fdopendir(duplicated_fd);
  if (directory == nullptr) {
    (void)close(duplicated_fd);
    return false;
  }

  bool valid = true;
  while (valid) {
    errno = 0;
    struct dirent* entry = readdir(directory);
    if (entry == nullptr) {
      if (errno != 0) {
        valid = false;
      }
      break;
    }
    if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    if (depth >= limits.max_depth || *entries >= limits.max_entries) {
      valid = false;
      break;
    }

    struct stat child_stat{};
    if (fstatat(directory_fd, entry->d_name, &child_stat, AT_SYMLINK_NOFOLLOW) != 0 ||
        (!IsSafeViteCacheDirectory(child_stat, session) &&
         !IsSafeViteCacheFile(child_stat, session))) {
      valid = false;
      break;
    }
    *entries += 1U;

    if (S_ISDIR(child_stat.st_mode)) {
      FileDescriptor child_fd(OpenDirectoryNameAt(directory_fd, entry->d_name));
      struct stat opened_child_stat{};
      if (child_fd.Get() < 0 || fstat(child_fd.Get(), &opened_child_stat) != 0 ||
          !IsSafeViteCacheDirectory(opened_child_stat, session) || !HasSafeAcl(child_fd.Get()) ||
          !SameStatIdentity(opened_child_stat,
                            Identity{static_cast<uint64_t>(child_stat.st_dev),
                                     static_cast<uint64_t>(child_stat.st_ino)}) ||
          !ScanViteCacheCanaryDirectory(child_fd.Get(), depth + 1U, session, limits, entries, files,
                                        aggregate_bytes, matcher) ||
          !RevalidateViteCacheChildLink(directory_fd, entry->d_name, opened_child_stat)) {
        valid = false;
        break;
      }
      continue;
    }

    if (*files >= limits.max_files ||
        static_cast<uint64_t>(child_stat.st_size) > limits.max_bytes - *aggregate_bytes ||
        !ScanViteCacheCanaryFile(directory_fd, entry->d_name, child_stat, session, matcher)) {
      valid = false;
      break;
    }
    *files += 1U;
    *aggregate_bytes += static_cast<uint64_t>(child_stat.st_size);
  }

  if (closedir(directory) != 0) {
    valid = false;
  }
  return valid && RevalidateSafeViteCacheDirectoryState(directory_fd, before, session);
}

bool ScanViteCacheCanariesInternal(ViteCacheSession* session, const ViteCacheLimitsNative& limits,
                                   const ViteCacheTokenHashes& token_hashes,
                                   bool* detected) {
  if (!ValidateViteCacheSessionAuthority(session)) {
    return false;
  }
  struct stat root_stat{};
  if (fstat(session->root_fd.Get(), &root_stat) != 0 ||
      !MatchesViteCacheRecord(root_stat, session->provenance.root)) {
    return false;
  }

  ViteCacheTreeResult tree;
  if (!ScanViteCacheTreeInternal(session, limits, &tree)) {
    return false;
  }
  for (const ViteCacheTreeEntry& entry : tree.entries) {
    if (!IsSafeViteCacheTreeEntry(entry, session)) {
      return false;
    }
  }

  uint32_t entries = 1U;
  uint32_t files = 0U;
  uint64_t aggregate_bytes = 0U;
  ViteCacheTokenMatcher matcher(token_hashes);
  if (!ScanViteCacheCanaryDirectory(session->root_fd.Get(), 0U, session, limits, &entries, &files,
                                    &aggregate_bytes, &matcher) ||
      !ValidateViteCacheSessionAuthority(session)) {
    return false;
  }
  *detected = matcher.detected;
  return true;
}

bool ParseViteCacheTokenHashes(napi_env env, napi_value value,
                               ViteCacheTokenHashes* output) {
  bool is_array = false;
  uint32_t length = 0;
  if (!IsNapiStatusOk(napi_is_array(env, value, &is_array)) || !is_array ||
      !IsNapiStatusOk(napi_get_array_length(env, value, &length)) || length == 0U ||
      length > kMaximumViteCacheTokenHashes) {
    ThrowCacheDenied(env);
    return false;
  }
  output->Clear();
  output->values.reserve(length);
  for (uint32_t index = 0; index < length; ++index) {
    napi_value item;
    std::string hash;
    if (!IsNapiStatusOk(napi_get_element(env, value, index, &item)) ||
        !GetString(env, item, &hash, 64U) || hash.size() != 64U) {
      ZeroizeString(&hash);
      ThrowCacheDenied(env);
      return false;
    }

    ViteCacheTokenHash parsed_hash{};
    bool valid = true;
    for (size_t character_index = 0; character_index < hash.size(); ++character_index) {
      const char character = hash[character_index];
      if (!((character >= 'a' && character <= 'f') || (character >= '0' && character <= '9'))) {
        valid = false;
        break;
      }
      parsed_hash[character_index] = static_cast<unsigned char>(character);
    }
    ZeroizeString(&hash);
    bool duplicate = false;
    if (valid && !MatchesViteCacheTokenHash(*output, parsed_hash, &duplicate, nullptr)) {
      valid = false;
    }
    if (!valid || duplicate) {
      ZeroizeMemory(parsed_hash.data(), parsed_hash.size());
      ThrowCacheDenied(env);
      return false;
    }
    output->values.push_back(parsed_hash);
    ZeroizeMemory(parsed_hash.data(), parsed_hash.size());
  }
  return true;
}
struct ViteCacheWatcher {
  napi_env env;
  ViteCacheSession* session;
  uv_timer_t timer{};
  bool timer_initialized = false;
  bool closed = false;
  bool reporting_failure = false;
  uint32_t polls_remaining = kMaximumViteCacheWatcherPolls;
  uint64_t fingerprint = 0;
  napi_ref on_event = nullptr;
  napi_ref on_failure = nullptr;
  napi_ref session_reference = nullptr;
  napi_ref self_reference = nullptr;
  bool watcher_slot_charged = false;
};

void CloseViteCacheWatcher(ViteCacheWatcher* watcher);

void RemoveViteCacheWatcher(ViteCacheWatcher* watcher) {
  if (watcher == nullptr || watcher->session == nullptr) {
    return;
  }
  std::vector<ViteCacheWatcher*>& watchers = watcher->session->watchers;
  const auto position = std::find(watchers.begin(), watchers.end(), watcher);
  if (position != watchers.end()) {
    watchers.erase(position);
  }
}

void ClearPendingException(napi_env env) {
  bool pending = false;
  napi_value ignored;
  if (IsNapiStatusOk(napi_is_exception_pending(env, &pending)) && pending) {
    (void)napi_get_and_clear_last_exception(env, &ignored);
  }
}

bool CallViteCacheWatcherCallback(ViteCacheWatcher* watcher, napi_ref callback,
                                  const char* event_name, bool sanitized_failure) {
  if (watcher->closed || callback == nullptr) {
    return false;
  }

  napi_handle_scope handle_scope;
  if (!IsNapiStatusOk(napi_open_handle_scope(watcher->env, &handle_scope))) {
    return false;
  }

  bool called = false;
  napi_value callback_value;
  napi_value receiver;
  napi_value event;
  do {
    if (!IsNapiStatusOk(napi_get_reference_value(watcher->env, callback, &callback_value)) ||
        !IsNapiStatusOk(napi_get_undefined(watcher->env, &receiver))) {
      break;
    }

    size_t argument_count = 0U;
    if (event_name != nullptr) {
      if (!IsNapiStatusOk(napi_create_string_utf8(watcher->env, event_name, NAPI_AUTO_LENGTH, &event))) {
        break;
      }
      argument_count = 1U;
    } else if (sanitized_failure) {
      napi_value code;
      napi_value message;
      if (!IsNapiStatusOk(napi_create_string_utf8(watcher->env, kNativeFailureCode,
                                                   NAPI_AUTO_LENGTH, &code)) ||
          !IsNapiStatusOk(napi_create_string_utf8(watcher->env, "Managed Vite cache watcher failed.",
                                                   NAPI_AUTO_LENGTH, &message)) ||
          !IsNapiStatusOk(napi_create_error(watcher->env, code, message, &event))) {
        break;
      }
      argument_count = 1U;
    }
    if (!IsNapiStatusOk(napi_call_function(watcher->env, receiver, callback_value, argument_count,
                                            argument_count == 0U ? nullptr : &event, nullptr))) {
      ClearPendingException(watcher->env);
      break;
    }
    called = true;
  } while (false);
  if (!IsNapiStatusOk(napi_close_handle_scope(watcher->env, handle_scope))) {
    return false;
  }
  return called;
}

uint64_t HashViteCacheValue(uint64_t current, uint64_t value) {
  constexpr uint64_t kOffset = 1469598103934665603ULL;
  constexpr uint64_t kPrime = 1099511628211ULL;
  if (current == 0U) {
    current = kOffset;
  }
  for (size_t index = 0; index < sizeof(value); ++index) {
    current ^= static_cast<unsigned char>(value >> (index * 8U));
    current *= kPrime;
  }
  return current;
}

uint64_t ViteCacheTreeFingerprint(const ViteCacheTreeResult& tree) {
  uint64_t fingerprint = 0U;
  for (const ViteCacheTreeEntry& entry : tree.entries) {
    fingerprint = HashViteCacheValue(fingerprint, entry.identity.device);
    fingerprint = HashViteCacheValue(fingerprint, entry.identity.inode);
    fingerprint = HashViteCacheValue(fingerprint, entry.has_parent_identity ? 1U : 0U);
    fingerprint = HashViteCacheValue(fingerprint, entry.parent_identity.device);
    fingerprint = HashViteCacheValue(fingerprint, entry.parent_identity.inode);
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.uid));
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.gid));
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.mode));
    fingerprint = HashViteCacheValue(fingerprint, entry.size_bytes);
    fingerprint = HashViteCacheValue(fingerprint, entry.link_count);
    fingerprint = HashViteCacheValue(fingerprint, entry.depth);
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.kind));
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.modified_seconds));
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.modified_nanoseconds));
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.changed_seconds));
    fingerprint = HashViteCacheValue(fingerprint, static_cast<uint64_t>(entry.changed_nanoseconds));
  }
  return fingerprint;
}

bool ReadViteCacheWatcherFingerprint(ViteCacheSession* session, uint64_t* output) {
  const ViteCacheLimitsNative limits{
      .max_entries = kMaximumViteCacheEntries,
      .max_files = kMaximumViteCacheFiles,
      .max_bytes = kMaximumViteCacheBytes,
      .max_depth = kMaximumViteCacheDepth,
  };
  ViteCacheTreeResult tree;
  if (!ScanViteCacheTreeInternal(session, limits, &tree)) {
    return false;
  }
  *output = ViteCacheTreeFingerprint(tree);
  return true;
}

bool TryAcquireViteCacheWatcherSlot() {
  uint32_t current = active_vite_cache_watchers.load(std::memory_order_relaxed);
  while (current < kMaximumViteCacheWatchers) {
    if (active_vite_cache_watchers.compare_exchange_weak(
            current, current + 1U, std::memory_order_acq_rel, std::memory_order_relaxed)) {
      return true;
    }
  }
  return false;
}

void ReleaseViteCacheWatcherSlot(ViteCacheWatcher* watcher) {
  if (watcher == nullptr || !watcher->watcher_slot_charged) {
    return;
  }
  watcher->watcher_slot_charged = false;
  (void)active_vite_cache_watchers.fetch_sub(1U, std::memory_order_acq_rel);
}

void CompleteViteCacheWatcherClose(uv_handle_t* handle) {
  auto* watcher = static_cast<ViteCacheWatcher*>(handle->data);
  watcher->timer_initialized = false;
  ReleaseViteCacheWatcherSlot(watcher);
  napi_ref self_reference = watcher->self_reference;
  watcher->self_reference = nullptr;
  if (self_reference != nullptr) {
    (void)napi_delete_reference(watcher->env, self_reference);
  }
}

void ReleaseViteCacheWatcherReferences(ViteCacheWatcher* watcher) {
  if (watcher->on_event != nullptr) {
    (void)napi_delete_reference(watcher->env, watcher->on_event);
    watcher->on_event = nullptr;
  }
  if (watcher->on_failure != nullptr) {
    (void)napi_delete_reference(watcher->env, watcher->on_failure);
    watcher->on_failure = nullptr;
  }
  if (watcher->session_reference != nullptr) {
    (void)napi_delete_reference(watcher->env, watcher->session_reference);
    watcher->session_reference = nullptr;
  }
}

void CloseViteCacheWatcher(ViteCacheWatcher* watcher) {
  if (watcher == nullptr || watcher->closed) {
    return;
  }
  watcher->closed = true;
  RemoveViteCacheWatcher(watcher);
  ReleaseViteCacheWatcherReferences(watcher);

  if (watcher->timer_initialized) {
    if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&watcher->timer))) {
      uv_timer_stop(&watcher->timer);
      uv_close(reinterpret_cast<uv_handle_t*>(&watcher->timer), CompleteViteCacheWatcherClose);
    }
    return;
  }
  ReleaseViteCacheWatcherSlot(watcher);

  napi_ref self_reference = watcher->self_reference;
  watcher->self_reference = nullptr;
  if (self_reference != nullptr) {
    (void)napi_delete_reference(watcher->env, self_reference);
  }
}

void ReportViteCacheWatcherFailure(ViteCacheWatcher* watcher) {
  if (watcher == nullptr || watcher->closed || watcher->reporting_failure) {
    return;
  }
  watcher->reporting_failure = true;
  (void)CallViteCacheWatcherCallback(watcher, watcher->on_failure, nullptr, true);
  CloseViteCacheWatcher(watcher);
}

void PollViteCacheWatcher(uv_timer_t* timer) {
  auto* watcher = static_cast<ViteCacheWatcher*>(timer->data);
  if (watcher == nullptr || watcher->closed) {
    return;
  }
  if (watcher->polls_remaining == 0U) {
    ReportViteCacheWatcherFailure(watcher);
    return;
  }
  watcher->polls_remaining -= 1U;

  uint64_t fingerprint = 0;
  if (!ReadViteCacheWatcherFingerprint(watcher->session, &fingerprint)) {
    ReportViteCacheWatcherFailure(watcher);
    return;
  }
  if (fingerprint == watcher->fingerprint) {
    return;
  }
  watcher->fingerprint = fingerprint;
  if (!CallViteCacheWatcherCallback(watcher, watcher->on_event, "changed", false)) {
    ReportViteCacheWatcherFailure(watcher);
  }
}

void CloseViteCacheSession(ViteCacheSession* session) {
  if (session == nullptr || session->closed) {
    return;
  }
  session->closed = true;
  while (!session->watchers.empty()) {
    CloseViteCacheWatcher(session->watchers.back());
  }
  session->root_fd.Reset();
  session->parent_fd.Reset();
  if (session->slot_charged) {
    ReleaseAuthoritySlot(&active_vite_cache_sessions);
    session->slot_charged = false;
  }
}

void FinalizeViteCacheSession(napi_env, void* data, void*) {
  auto* session = static_cast<ViteCacheSession*>(data);
  CloseViteCacheSession(session);
  delete session;
}

void FinalizeViteCacheWatcher(napi_env, void* data, void*) {
  auto* watcher = static_cast<ViteCacheWatcher*>(data);
  CloseViteCacheWatcher(watcher);
  delete watcher;
}

bool RequireViteCacheWatcher(napi_env env, napi_value value, ViteCacheWatcher** output) {
  bool is_tagged = false;
  if (!GetObject(env, value, &value) ||
      !IsNapiStatusOk(napi_check_object_type_tag(env, value, &kViteCacheWatcherTypeTag, &is_tagged)) ||
      !is_tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowCacheDenied(env);
    return false;
  }
  return true;
}
napi_value OpenViteCacheSession(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value provenance_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "provenance", &provenance_value)) {
    return nullptr;
  }

  ViteCacheProvenanceNative provenance;
  if (!ParseViteCacheProvenance(env, provenance_value, &provenance)) {
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_vite_cache_sessions, kMaximumViteCacheSessions)) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  FileDescriptor parent_fd;
  FileDescriptor root_fd;
  if (!OpenViteCacheAuthority(provenance, &parent_fd, &root_fd)) {
    ReleaseAuthoritySlot(&active_vite_cache_sessions);
    ThrowCacheDenied(env);
    return nullptr;
  }

  auto* session = new (std::nothrow) ViteCacheSession{
      .parent_fd = std::move(parent_fd),
      .root_fd = std::move(root_fd),
      .provenance = std::move(provenance),
      .slot_charged = true,
  };
  if (session == nullptr) {
    ReleaseAuthoritySlot(&active_vite_cache_sessions);
    ThrowCacheFailure(env);
    return nullptr;
  }

  napi_value session_value;
  napi_value root;
  napi_value parent;
  napi_value result;
  if (!IsNapiStatusOk(napi_create_object(env, &session_value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, session_value, &kViteCacheSessionTypeTag))) {
    CloseViteCacheSession(session);
    delete session;
    ThrowCacheFailure(env);
    return nullptr;
  }
  if (!IsNapiStatusOk(napi_wrap(env, session_value, session, FinalizeViteCacheSession, nullptr,
                                nullptr))) {
    CloseViteCacheSession(session);
    delete session;
    ThrowCacheFailure(env);
    return nullptr;
  }
  if (!CreateViteCacheRecord(env, session->provenance.root, &root) ||
      !CreateViteCacheRecord(env, session->provenance.parent, &parent) ||
      !IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "session", session_value)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "root", root)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "parent", parent))) {
    CloseViteCacheSession(session);
    ThrowCacheFailure(env);
    return nullptr;
  }
  return result;
}

napi_value ScanViteCacheTree(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value session_value;
  napi_value limits_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", &session_value) ||
      !GetRequiredProperty(env, options, "limits", &limits_value)) {
    return nullptr;
  }
  ViteCacheSession* session = nullptr;
  ViteCacheLimitsNative limits{};
  if (!RequireViteCacheSession(env, session_value, &session) ||
      !ParseViteCacheLimits(env, limits_value, &limits)) {
    return nullptr;
  }

  ViteCacheTreeResult tree;
  if (!ScanViteCacheTreeInternal(session, limits, &tree)) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  napi_value result;
  if (!CreateViteCacheTreeResult(env, session, tree, &result)) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  return result;
}

napi_value ScanViteCacheCanaries(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value session_value;
  napi_value limits_value;
  napi_value token_hashes_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", &session_value) ||
      !GetRequiredProperty(env, options, "limits", &limits_value) ||
      !GetRequiredProperty(env, options, "tokenHashes", &token_hashes_value)) {
    return nullptr;
  }
  ViteCacheSession* session = nullptr;
  ViteCacheLimitsNative limits{};
  ViteCacheTokenHashes token_hashes;
  if (!RequireViteCacheSession(env, session_value, &session) ||
      !ParseViteCacheLimits(env, limits_value, &limits) ||
      !ParseViteCacheTokenHashes(env, token_hashes_value, &token_hashes)) {
    return nullptr;
  }

  bool detected = false;
  if (!ScanViteCacheCanariesInternal(session, limits, token_hashes, &detected)) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  napi_value result;
  napi_value detected_value;
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_get_boolean(env, detected, &detected_value)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "detected", detected_value))) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  return result;
}
bool ParseViteCacheWatcherCallback(napi_env env, napi_value value, napi_value* output) {
  napi_valuetype type;
  if (!IsNapiStatusOk(napi_typeof(env, value, &type)) || type != napi_function) {
    ThrowCacheDenied(env);
    return false;
  }
  *output = value;
  return true;
}

napi_value WatchViteCacheTree(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value session_value;
  napi_value on_event_value;
  napi_value on_failure_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", &session_value) ||
      !GetRequiredProperty(env, options, "onEvent", &on_event_value) ||
      !GetRequiredProperty(env, options, "onFailure", &on_failure_value) ||
      !ParseViteCacheWatcherCallback(env, on_event_value, &on_event_value) ||
      !ParseViteCacheWatcherCallback(env, on_failure_value, &on_failure_value)) {
    return nullptr;
  }
  ViteCacheSession* session = nullptr;
  if (!RequireViteCacheSession(env, session_value, &session)) {
    return nullptr;
  }
  if (active_vite_cache_watchers.load(std::memory_order_acquire) >=
      kMaximumViteCacheWatchers) {
    ThrowCacheFailure(env);
    return nullptr;
  }

  uint64_t fingerprint = 0;
  if (!ReadViteCacheWatcherFingerprint(session, &fingerprint)) {
    ThrowCacheFailure(env);
    return nullptr;
  }

  auto* watcher = new (std::nothrow) ViteCacheWatcher{
      .env = env,
      .session = session,
      .fingerprint = fingerprint,
  };
  if (watcher == nullptr) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  if (!IsNapiStatusOk(napi_create_reference(env, on_event_value, 1U, &watcher->on_event)) ||
      !IsNapiStatusOk(napi_create_reference(env, on_failure_value, 1U, &watcher->on_failure)) ||
      !IsNapiStatusOk(napi_create_reference(env, session_value, 1U, &watcher->session_reference))) {
    ReleaseViteCacheWatcherReferences(watcher);
    delete watcher;
    ThrowCacheFailure(env);
    return nullptr;
  }

  napi_value watcher_value;
  if (!IsNapiStatusOk(napi_create_object(env, &watcher_value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, watcher_value, &kViteCacheWatcherTypeTag))) {
    ReleaseViteCacheWatcherReferences(watcher);
    delete watcher;
    ThrowCacheFailure(env);
    return nullptr;
  }
  if (!IsNapiStatusOk(napi_wrap(env, watcher_value, watcher, FinalizeViteCacheWatcher, nullptr, nullptr))) {
    ReleaseViteCacheWatcherReferences(watcher);
    delete watcher;
    ThrowCacheFailure(env);
    return nullptr;
  }
  if (!IsNapiStatusOk(napi_create_reference(env, watcher_value, 1U, &watcher->self_reference))) {
    CloseViteCacheWatcher(watcher);
    ThrowCacheFailure(env);
    return nullptr;
  }
  if (!TryAcquireViteCacheWatcherSlot()) {
    CloseViteCacheWatcher(watcher);
    ThrowCacheFailure(env);
    return nullptr;
  }
  watcher->watcher_slot_charged = true;

  uv_loop_t* loop = nullptr;
  if (!IsNapiStatusOk(napi_get_uv_event_loop(env, &loop)) ||
      uv_timer_init(loop, &watcher->timer) != 0) {
    CloseViteCacheWatcher(watcher);
    ThrowCacheFailure(env);
    return nullptr;
  }
  watcher->timer_initialized = true;
  watcher->timer.data = watcher;
  session->watchers.push_back(watcher);
  if (uv_timer_start(&watcher->timer, PollViteCacheWatcher, kViteCacheWatcherIntervalMilliseconds,
                     kViteCacheWatcherIntervalMilliseconds) != 0) {
    CloseViteCacheWatcher(watcher);
    ThrowCacheFailure(env);
    return nullptr;
  }
  return watcher_value;
}

napi_value CloseViteCacheWatcherBinding(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value watcher_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "watcher", &watcher_value)) {
    return nullptr;
  }
  ViteCacheWatcher* watcher = nullptr;
  if (!RequireViteCacheWatcher(env, watcher_value, &watcher)) {
    return nullptr;
  }
  CloseViteCacheWatcher(watcher);
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  return result;
}

napi_value CloseViteCacheSessionBinding(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value session_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", &session_value)) {
    return nullptr;
  }
  ViteCacheSession* session = nullptr;
  if (!UnwrapViteCacheSession(env, session_value, &session)) {
    return nullptr;
  }
  CloseViteCacheSession(session);
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowCacheFailure(env);
    return nullptr;
  }
  return result;
}
constexpr uint32_t kMaximumViteSnapshotEntries = 2000U;
constexpr uint32_t kMaximumViteSnapshotDirectories = 1000U;
constexpr uint32_t kMaximumViteSnapshotFiles = 1000U;
constexpr uint64_t kMaximumViteSnapshotBytes = 64U * 1024U * 1024U;
constexpr uint32_t kMaximumViteSnapshotDepth = 8U;
constexpr uint32_t kMaximumViteSnapshotCommitmentBytes = 1024U * 1024U;
constexpr uint32_t kMaximumViteSnapshotSessions = 8U;
constexpr uint32_t kMaximumViteSnapshotStagings = 64U;
constexpr uint32_t kMaximumViteSnapshotPublished = 64U;
std::atomic<uint32_t> active_vite_snapshot_sessions{0U};
std::atomic<uint32_t> active_vite_snapshot_stagings{0U};
std::atomic<uint32_t> active_vite_snapshot_published{0U};
const napi_type_tag kViteSnapshotSessionTypeTag = {0x4f614a48b9ce4b0cULL, 0xa964584765bbb18aULL};
const napi_type_tag kViteSnapshotStagingTypeTag = {0x79cdff8af2914a64ULL, 0x940c9e3df25b2c1fULL};
const napi_type_tag kViteSnapshotPublishedTypeTag = {0x735eb1e29b7244baULL, 0xaa22c8934a1d758eULL};

struct ViteSnapshotSession;
struct ViteSnapshotStaging;
struct ViteSnapshotPublished;

struct ViteSnapshotEnvironment {
  napi_env env = nullptr;
  bool cleanup_started = false;
  std::vector<ViteSnapshotSession*> finalizing_sessions;
  std::vector<ViteSnapshotStaging*> finalizing_stagings;
  std::vector<ViteSnapshotPublished*> finalizing_published;
};

struct ViteSnapshotSession {
  ViteSnapshotEnvironment* environment = nullptr;
  FileDescriptor root_parent_fd;
  FileDescriptor root_fd;
  FileDescriptor scene_glass_fd;
  FileDescriptor runtime_fd;
  FileDescriptor staging_parent_fd;
  FileDescriptor published_parent_fd;
  FileDescriptor provenance_fd;
  Identity root_parent_identity;
  Identity root_identity;
  Identity scene_glass_identity;
  Identity runtime_identity;
  Identity staging_parent_identity;
  Identity published_parent_identity;
  Identity provenance_identity;
  std::string root_name;
  std::string canonical_root_path;
  std::vector<Identity> canonical_ancestor_identities;
  uid_t owner_uid;
  bool closed = false;
  bool slot_charged = false;
  bool finalization_retained = false;
  std::vector<ViteSnapshotStaging*> stagings;
  std::vector<ViteSnapshotPublished*> published;
};

struct ViteSnapshotStaging {
  napi_env env;
  ViteSnapshotSession* session;
  napi_ref session_reference = nullptr;
  FileDescriptor fd;
  Identity identity;
  std::string install_id;
  std::string name;
  uint32_t file_count = 0U;
  uint64_t aggregate_bytes = 0U;
  bool closed = false;
  bool published = false;
  bool publication_pending = false;
  bool located_in_published_parent = false;
  bool slot_charged = false;
  bool finalization_retained = false;
};

struct ViteSnapshotPublished {
  napi_env env;
  ViteSnapshotSession* session;
  napi_ref session_reference = nullptr;
  FileDescriptor fd;
  Identity identity;
  std::string install_id;
  FileDescriptor commitment_fd;
  Identity commitment_identity;
  std::string commitment_name;
  bool commitment_cleanup_pending = false;
  bool commitment_unlinked = false;
  ViteSnapshotStaging* pending_staging = nullptr;
  bool closed = false;
  bool slot_charged = false;
  bool finalization_retained = false;
};

ViteSnapshotEnvironment* GetViteSnapshotEnvironment(napi_env env) {
  void* data = nullptr;
  if (!IsNapiStatusOk(napi_get_instance_data(env, &data)) || data == nullptr) {
    return nullptr;
  }
  auto* environment = static_cast<ViteSnapshotEnvironment*>(data);
  return environment->env == env ? environment : nullptr;
}

void CleanupViteSnapshotEnvironment(void* data);

void FinalizeViteSnapshotEnvironment(napi_env, void* data, void*) {
  auto* environment = static_cast<ViteSnapshotEnvironment*>(data);
  if (environment != nullptr) {
    CleanupViteSnapshotEnvironment(environment);
    delete environment;
  }
}

void ThrowSnapshotDenied(napi_env env) {
  Throw(env, kPathDeniedCode, "secure native snapshot operation denied");
}

void ThrowSnapshotFailure(napi_env env) {
  Throw(env, kNativeFailureCode, "secure native snapshot operation failed");
}

bool IsViteSnapshotInstallId(const std::string& value) {
  return IsViteCacheInstallId(value);
}
bool IsViteSnapshotStagingName(const std::string& value) {
  if (value.empty() || value.size() > kMaximumPathComponentBytes) {
    return false;
  }
  for (const char character : value) {
    if (!((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || character == '_' || character == '-')) {
      return false;
    }
  }
  return true;
}


bool IsSafeViteSnapshotDirectory(const struct stat& stat, uid_t owner_uid, uint64_t root_device) {
  return S_ISDIR(stat.st_mode) && stat.st_uid == owner_uid &&
         static_cast<uint64_t>(stat.st_dev) == root_device &&
         static_cast<mode_t>(stat.st_mode & 07777) == 0700U;
}

// The user's project root is not setup-owned, so it must not be forced to 0700
// (that would require chmod'ing the host project). It is safe as long as it is a
// directory owned by the same user on the same device with no group/other write
// access. The setup-owned `.scg` runtime subtree keeps the strict 0700 policy.
bool IsSafeViteSnapshotProjectRoot(const struct stat& stat, uid_t owner_uid,
                                   uint64_t root_device) {
  return S_ISDIR(stat.st_mode) && stat.st_uid == owner_uid &&
         static_cast<uint64_t>(stat.st_dev) == root_device &&
         (stat.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

bool IsSafeViteSnapshotFile(const struct stat& stat, uid_t owner_uid, uint64_t root_device) {
  return S_ISREG(stat.st_mode) && stat.st_nlink == 1 && stat.st_size >= 0 &&
         stat.st_uid == owner_uid && static_cast<uint64_t>(stat.st_dev) == root_device &&
         static_cast<mode_t>(stat.st_mode & 07777) == 0600U;
}

bool SameSnapshotIdentity(const struct stat& stat, const Identity& identity) {
  return static_cast<uint64_t>(stat.st_dev) == identity.device &&
         static_cast<uint64_t>(stat.st_ino) == identity.inode;
}

Identity SnapshotIdentityFromStat(const struct stat& stat) {
  return Identity{static_cast<uint64_t>(stat.st_dev), static_cast<uint64_t>(stat.st_ino)};
}

bool ValidateSnapshotDirectoryFd(int fd, uid_t owner_uid, uint64_t root_device,
                                 const Identity& expected) {
  struct stat stat{};
  return fd >= 0 && fstat(fd, &stat) == 0 &&
         IsSafeViteSnapshotDirectory(stat, owner_uid, root_device) &&
         SameSnapshotIdentity(stat, expected) && HasSafeAcl(fd);
}

bool ValidateSnapshotLinkedDirectory(int parent_fd, const char* name, int directory_fd,
                                     uid_t owner_uid, uint64_t root_device,
                                     const Identity& expected) {
  struct stat linked{};
  return fstatat(parent_fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         IsSafeViteSnapshotDirectory(linked, owner_uid, root_device) &&
         SameSnapshotIdentity(linked, expected) &&
         ValidateSnapshotDirectoryFd(directory_fd, owner_uid, root_device, expected);
}
// Project-root variants: the user's project root is not setup-owned, so it uses
// the relaxed IsSafeViteSnapshotProjectRoot policy (no group/other write) instead
// of the strict 0700 policy used for the setup-owned `.scg` runtime subtree.
bool ValidateSnapshotProjectRootFd(int fd, uid_t owner_uid, uint64_t root_device,
                                   const Identity& expected) {
  struct stat stat{};
  return fd >= 0 && fstat(fd, &stat) == 0 &&
         IsSafeViteSnapshotProjectRoot(stat, owner_uid, root_device) &&
         SameSnapshotIdentity(stat, expected) && HasSafeAcl(fd);
}
bool ValidateSnapshotLinkedProjectRoot(int parent_fd, const char* name, int directory_fd,
                                       uid_t owner_uid, uint64_t root_device,
                                       const Identity& expected) {
  struct stat linked{};
  return fstatat(parent_fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         IsSafeViteSnapshotProjectRoot(linked, owner_uid, root_device) &&
         SameSnapshotIdentity(linked, expected) &&
         ValidateSnapshotProjectRootFd(directory_fd, owner_uid, root_device, expected);
}
bool ValidateSnapshotLinkedFile(int parent_fd, const char* name, int file_fd,
                                const Identity& expected) {
  struct stat linked{};
  struct stat opened{};
  return file_fd >= 0 && fstatat(parent_fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         fstat(file_fd, &opened) == 0 && SameSnapshotIdentity(linked, expected) &&
         SameSnapshotIdentity(opened, expected);
}

bool RemoveSnapshotRetainedDirectory(int parent_fd, const char* name, int directory_fd,
                                     uid_t owner_uid, uint64_t root_device,
                                     const Identity& expected) {
  if (!ValidateSnapshotLinkedDirectory(parent_fd, name, directory_fd, owner_uid, root_device,
                                       expected)) {
    return false;
  }
  struct stat linked{};
  return fstatat(parent_fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         SameSnapshotIdentity(linked, expected) && unlinkat(parent_fd, name, AT_REMOVEDIR) == 0;
}

bool RemoveSnapshotRetainedFile(int parent_fd, const char* name, int file_fd,
                                const Identity& expected) {
  if (!ValidateSnapshotLinkedFile(parent_fd, name, file_fd, expected)) {
    return false;
  }
  struct stat opened{};
  struct stat linked{};
  return fstat(file_fd, &opened) == 0 && SameSnapshotIdentity(opened, expected) &&
         fstatat(parent_fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         SameSnapshotIdentity(linked, expected) && unlinkat(parent_fd, name, 0) == 0;
}

bool OpenOrCreateViteSnapshotDirectory(int parent_fd, const char* name, uid_t owner_uid,
                                       uint64_t root_device, FileDescriptor* output,
                                       Identity* identity) {
  if (mkdirat(parent_fd, name, 0700) != 0 && errno != EEXIST) {
    return false;
  }
  FileDescriptor directory(OpenDirectoryAt(parent_fd, name));
  struct stat stat{};
  if (directory.Get() < 0 || fstat(directory.Get(), &stat) != 0 ||
      !IsSafeViteSnapshotDirectory(stat, owner_uid, root_device) ||
      !HasSafeAcl(directory.Get())) {
    return false;
  }
  const Identity captured = SnapshotIdentityFromStat(stat);
  if (!ValidateSnapshotLinkedDirectory(parent_fd, name, directory.Get(), owner_uid, root_device,
                                       captured)) {
    return false;
  }
  if (fsync(parent_fd) != 0) {
    return false;
  }
  *output = std::move(directory);
  *identity = captured;
  return true;
}

bool OpenViteSnapshotRoot(const std::string& canonical_path, const Identity& expected_root,
                          uid_t owner_uid, FileDescriptor* parent_fd, FileDescriptor* root_fd,
                          Identity* parent_identity, std::string* root_name,
                          std::vector<Identity>* canonical_ancestor_identities) {
  std::vector<std::string> components;
  if (canonical_ancestor_identities == nullptr ||
      !SplitCanonicalPath(canonical_path, &components) || components.empty()) {
    return false;
  }

  FileDescriptor current(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  struct stat current_stat{};
  if (current.Get() < 0 || fstat(current.Get(), &current_stat) != 0 ||
      !S_ISDIR(current_stat.st_mode)) {
    return false;
  }
  std::vector<Identity> ancestors;
  ancestors.reserve(components.size() + 1U);
  ancestors.push_back(SnapshotIdentityFromStat(current_stat));
  for (size_t index = 0; index + 1U < components.size(); ++index) {
    FileDescriptor next(OpenDirectoryAt(current.Get(), components[index]));
    struct stat next_stat{};
    if (next.Get() < 0 || fstat(next.Get(), &next_stat) != 0 || !S_ISDIR(next_stat.st_mode)) {
      return false;
    }
    ancestors.push_back(SnapshotIdentityFromStat(next_stat));
    current = std::move(next);
  }

  struct stat parent_stat{};
  struct stat linked_root{};
  if (fstat(current.Get(), &parent_stat) != 0 ||
      fstatat(current.Get(), components.back().c_str(), &linked_root, AT_SYMLINK_NOFOLLOW) != 0 ||
      !S_ISDIR(linked_root.st_mode) || !SameSnapshotIdentity(linked_root, expected_root)) {
    return false;
  }
  FileDescriptor root(OpenDirectoryAt(current.Get(), components.back()));
  struct stat root_stat{};
  if (root.Get() < 0 || fstat(root.Get(), &root_stat) != 0 ||
      !IsSafeViteSnapshotProjectRoot(root_stat, owner_uid,
                                     static_cast<uint64_t>(root_stat.st_dev)) ||
      !SameSnapshotIdentity(root_stat, expected_root) || !HasSafeAcl(root.Get()) ||
      !SameSnapshotIdentity(linked_root, expected_root)) {
    return false;
  }

  ancestors.push_back(SnapshotIdentityFromStat(root_stat));
  *parent_identity = SnapshotIdentityFromStat(parent_stat);
  *root_name = components.back();
  *canonical_ancestor_identities = std::move(ancestors);
  *parent_fd = std::move(current);
  *root_fd = std::move(root);
  return true;
}

bool ValidateViteSnapshotCanonicalAncestorChain(
    const std::string& canonical_path, const std::vector<Identity>& expected_identities) {
  std::vector<std::string> components;
  if (!SplitCanonicalPath(canonical_path, &components) || components.empty() ||
      expected_identities.size() != components.size() + 1U) {
    return false;
  }
  FileDescriptor current(open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
  struct stat current_stat{};
  if (current.Get() < 0 || fstat(current.Get(), &current_stat) != 0 ||
      !S_ISDIR(current_stat.st_mode) ||
      !SameSnapshotIdentity(current_stat, expected_identities.front())) {
    return false;
  }
  for (size_t index = 0; index < components.size(); ++index) {
    FileDescriptor next(OpenDirectoryAt(current.Get(), components[index]));
    struct stat next_stat{};
    if (next.Get() < 0 || fstat(next.Get(), &next_stat) != 0 || !S_ISDIR(next_stat.st_mode) ||
        !SameSnapshotIdentity(next_stat, expected_identities[index + 1U])) {
      return false;
    }
    current = std::move(next);
  }
  return true;
}

bool ValidateViteSnapshotSessionAuthority(ViteSnapshotSession* session) {
  if (session == nullptr || session->closed ||
      !ValidateViteSnapshotCanonicalAncestorChain(session->canonical_root_path,
                                                  session->canonical_ancestor_identities)) {
    return false;
  }
  const uint64_t root_device = session->root_identity.device;
  struct stat parent_stat{};
  if (session->root_parent_fd.Get() < 0 || fstat(session->root_parent_fd.Get(), &parent_stat) != 0 ||
      !S_ISDIR(parent_stat.st_mode) ||
      !SameSnapshotIdentity(parent_stat, session->root_parent_identity) ||
      !ValidateSnapshotLinkedProjectRoot(session->root_parent_fd.Get(), session->root_name.c_str(),
                                         session->root_fd.Get(), session->owner_uid, root_device,
                                         session->root_identity) ||
      !ValidateSnapshotLinkedDirectory(session->root_fd.Get(), ".scg",
                                       session->scene_glass_fd.Get(), session->owner_uid, root_device,
                                       session->scene_glass_identity) ||
      !ValidateSnapshotLinkedDirectory(session->scene_glass_fd.Get(), "runtime",
                                       session->runtime_fd.Get(), session->owner_uid, root_device,
                                       session->runtime_identity) ||
      !ValidateSnapshotLinkedDirectory(session->runtime_fd.Get(), "vite-staging",
                                       session->staging_parent_fd.Get(), session->owner_uid,
                                       root_device, session->staging_parent_identity) ||
      !ValidateSnapshotLinkedDirectory(session->runtime_fd.Get(), "vite-root",
                                       session->published_parent_fd.Get(), session->owner_uid,
                                       root_device, session->published_parent_identity) ||
      !ValidateSnapshotLinkedDirectory(session->runtime_fd.Get(), "vite-provenance",
                                       session->provenance_fd.Get(), session->owner_uid, root_device,
                                       session->provenance_identity)) {
    return false;
  }
  return true;
}

bool UnwrapViteSnapshotSession(napi_env env, napi_value value, ViteSnapshotSession** output) {
  bool tagged = false;
  if (!GetObject(env, value, &value) ||
      !IsNapiStatusOk(
          napi_check_object_type_tag(env, value, &kViteSnapshotSessionTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr || (*output)->environment == nullptr ||
      (*output)->environment->env != env || (*output)->environment->cleanup_started) {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool RequireViteSnapshotSession(napi_env env, napi_value value, ViteSnapshotSession** output) {
  if (!UnwrapViteSnapshotSession(env, value, output)) {
    return false;
  }
  if (!ValidateViteSnapshotSessionAuthority(*output)) {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool ParseViteSnapshotSessionOptions(napi_env env, napi_callback_info info, std::string* project_root,
                                     Identity* approved_root_identity, uid_t* owner_uid) {
  napi_value options;
  napi_value project_root_value;
  napi_value identity_value;
  uint32_t parsed_owner = 0U;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "projectRoot", &project_root_value) ||
      !GetRequiredProperty(env, options, "approvedRootIdentity", &identity_value) ||
      !ParseCanonicalAbsolutePath(env, project_root_value, project_root) ||
      !ParseIdentity(env, identity_value, approved_root_identity) ||
      !GetRequiredUint32(env, options, "expectedOwnerUid", UINT32_MAX, &parsed_owner) ||
      parsed_owner != static_cast<uint32_t>(geteuid())) {
    if (parsed_owner != static_cast<uint32_t>(geteuid())) {
      ThrowSnapshotDenied(env);
    }
    return false;
  }
  *owner_uid = static_cast<uid_t>(parsed_owner);
  return true;
}

bool ParseViteSnapshotStagingOptions(napi_env env, napi_callback_info info, napi_value* session_value,
                                     Identity* approved_root_identity, std::string* install_id,
                                     std::string* staging_name) {
  napi_value options;
  napi_value identity_value;
  napi_value install_id_value;
  napi_value staging_name_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", session_value) ||
      !GetRequiredProperty(env, options, "approvedRootIdentity", &identity_value) ||
      !GetRequiredProperty(env, options, "installId", &install_id_value) ||
      !GetRequiredProperty(env, options, "stagingName", &staging_name_value) ||
      !ParseIdentity(env, identity_value, approved_root_identity) ||
      !GetString(env, install_id_value, install_id, 128U) ||
      !GetString(env, staging_name_value, staging_name, kMaximumPathComponentBytes) ||
      !IsViteSnapshotInstallId(*install_id) || !IsViteSnapshotStagingName(*staging_name) ||
      staging_name->size() <= install_id->size() ||
      staging_name->compare(0U, install_id->size(), *install_id) != 0 ||
      (*staging_name)[install_id->size()] != '-') {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool ParseViteSnapshotWriteOptions(napi_env env, napi_callback_info info, napi_value* staging_value,
                                   std::string* relative_path, SensitiveBytes* bytes) {
  napi_value options;
  napi_value relative_path_value;
  napi_value bytes_value;
  uint32_t mode = 0U;
  bool is_buffer = false;
  void* source = nullptr;
  size_t source_length = 0U;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "staging", staging_value) ||
      !GetRequiredProperty(env, options, "relativePath", &relative_path_value) ||
      !GetRequiredProperty(env, options, "bytes", &bytes_value) ||
      !GetString(env, relative_path_value, relative_path, kMaximumPathBytes) ||
      !GetRequiredUint32(env, options, "mode", 07777U, &mode) || mode != 0600U ||
      !IsNapiStatusOk(napi_is_buffer(env, bytes_value, &is_buffer)) || !is_buffer ||
      !IsNapiStatusOk(napi_get_buffer_info(env, bytes_value, &source, &source_length)) ||
      source_length > kMaximumViteSnapshotBytes) {
    ThrowSnapshotDenied(env);
    return false;
  }
  std::vector<std::string> components;
  if (!ParseComponents(env, *relative_path, false, &components) || components.empty() ||
      components.size() > kMaximumViteSnapshotDepth) {
    return false;
  }
  SensitiveBytes copied(source_length);
  if (source_length != 0U) {
    std::memcpy(copied.Data(), source, source_length);
  }
  *bytes = std::move(copied);
  return true;
}

bool ParseViteSnapshotPublishedOptions(napi_env env, napi_callback_info info, napi_value* staging_value,
                                       Identity* approved_root_identity, std::string* install_id) {
  napi_value options;
  napi_value identity_value;
  napi_value install_id_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "staging", staging_value) ||
      !GetRequiredProperty(env, options, "approvedRootIdentity", &identity_value) ||
      !GetRequiredProperty(env, options, "installId", &install_id_value) ||
      !ParseIdentity(env, identity_value, approved_root_identity) ||
      !GetString(env, install_id_value, install_id, 128U) || !IsViteSnapshotInstallId(*install_id)) {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool ParseViteSnapshotCommitmentOptions(napi_env env, napi_callback_info info, napi_value* published_value,
                                        std::string* install_id, SensitiveBytes* bytes) {
  napi_value options;
  napi_value install_id_value;
  napi_value bytes_value;
  bool is_buffer = false;
  void* source = nullptr;
  size_t source_length = 0U;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "published", published_value) ||
      !GetRequiredProperty(env, options, "installId", &install_id_value) ||
      !GetRequiredProperty(env, options, "bytes", &bytes_value) ||
      !GetString(env, install_id_value, install_id, 128U) || !IsViteSnapshotInstallId(*install_id) ||
      !IsNapiStatusOk(napi_is_buffer(env, bytes_value, &is_buffer)) || !is_buffer ||
      !IsNapiStatusOk(napi_get_buffer_info(env, bytes_value, &source, &source_length)) ||
      source_length > kMaximumViteSnapshotCommitmentBytes) {
    ThrowSnapshotDenied(env);
    return false;
  }
  SensitiveBytes copied(source_length);
  if (source_length != 0U) {
    std::memcpy(copied.Data(), source, source_length);
  }
  *bytes = std::move(copied);
  return true;
}

bool ParseSingleViteSnapshotHandleOption(napi_env env, napi_callback_info info, const char* name,
                                         napi_value* output) {
  napi_value options;
  return GetSingleObjectArgument(env, info, &options) &&
         GetRequiredProperty(env, options, name, output);
}

void RemoveViteSnapshotStaging(ViteSnapshotStaging* staging) {
  if (staging == nullptr || staging->session == nullptr) {
    return;
  }
  std::vector<ViteSnapshotStaging*>& values = staging->session->stagings;
  const auto position = std::find(values.begin(), values.end(), staging);
  if (position != values.end()) {
    values.erase(position);
  }
}

void RemoveViteSnapshotPublished(ViteSnapshotPublished* published) {
  if (published == nullptr || published->session == nullptr) {
    return;
  }
  std::vector<ViteSnapshotPublished*>& values = published->session->published;
  const auto position = std::find(values.begin(), values.end(), published);
  if (position != values.end()) {
    values.erase(position);
  }
}

void CloseViteSnapshotStaging(ViteSnapshotStaging* staging) {
  if (staging == nullptr || staging->closed) {
    return;
  }
  staging->closed = true;
  staging->fd.Reset();
  RemoveViteSnapshotStaging(staging);
  if (staging->session_reference != nullptr) {
    (void)napi_delete_reference(staging->env, staging->session_reference);
    staging->session_reference = nullptr;
  }
  ZeroizeString(&staging->install_id);
  ZeroizeString(&staging->name);
  if (staging->slot_charged) {
    ReleaseAuthoritySlot(&active_vite_snapshot_stagings);
    staging->slot_charged = false;
  }
}

void CloseViteSnapshotPublished(ViteSnapshotPublished* published) {
  if (published == nullptr || published->closed || published->commitment_cleanup_pending) {
    return;
  }
  published->closed = true;
  published->pending_staging = nullptr;
  published->commitment_fd.Reset();
  RemoveViteSnapshotPublished(published);
  published->fd.Reset();
  if (published->session_reference != nullptr) {
    (void)napi_delete_reference(published->env, published->session_reference);
    published->session_reference = nullptr;
  }
  ZeroizeString(&published->commitment_name);
  ZeroizeString(&published->install_id);
  if (published->slot_charged) {
    ReleaseAuthoritySlot(&active_vite_snapshot_published);
    published->slot_charged = false;
  }
}
void CloseViteSnapshotPendingPublished(ViteSnapshotStaging* staging) {
  if (staging == nullptr || staging->session == nullptr) {
    return;
  }
  const std::vector<ViteSnapshotPublished*> values = staging->session->published;
  for (ViteSnapshotPublished* published : values) {
    if (published != nullptr && published->pending_staging == staging) {
      published->pending_staging = nullptr;
      CloseViteSnapshotPublished(published);
    }
  }
}

bool CloseViteSnapshotSession(ViteSnapshotSession* session) {
  if (session == nullptr || session->closed) {
    return true;
  }
  for (const ViteSnapshotStaging* staging : session->stagings) {
    if (staging != nullptr && staging->publication_pending) {
      return false;
    }
  }
  for (const ViteSnapshotPublished* published : session->published) {
    if (published != nullptr && published->commitment_cleanup_pending) {
      return false;
    }
  }
  session->closed = true;
  while (!session->stagings.empty()) {
    CloseViteSnapshotStaging(session->stagings.back());
  }
  while (!session->published.empty()) {
    CloseViteSnapshotPublished(session->published.back());
  }
  session->provenance_fd.Reset();
  session->published_parent_fd.Reset();
  session->staging_parent_fd.Reset();
  session->runtime_fd.Reset();
  session->scene_glass_fd.Reset();
  session->root_fd.Reset();
  session->root_parent_fd.Reset();
  ZeroizeString(&session->root_name);
  ZeroizeString(&session->canonical_root_path);
  session->canonical_ancestor_identities.clear();
  if (session->slot_charged) {
    ReleaseAuthoritySlot(&active_vite_snapshot_sessions);
    session->slot_charged = false;
  }
  return true;
}

bool FinalizeViteSnapshotStaging(ViteSnapshotStaging* staging);
bool FinalizeViteSnapshotPublished(ViteSnapshotPublished* published);
bool DrainRetainedViteSnapshotFinalizers(napi_env env);

void ClearViteSnapshotSessionReferences(ViteSnapshotSession* session) {
  if (session == nullptr) {
    return;
  }
  for (ViteSnapshotStaging* staging : session->stagings) {
    if (staging != nullptr) {
      staging->session_reference = nullptr;
    }
  }
  for (ViteSnapshotPublished* published : session->published) {
    if (published != nullptr) {
      published->session_reference = nullptr;
    }
  }
}

void ReleaseViteSnapshotStagingForEnvironmentCleanup(ViteSnapshotStaging* staging) {
  if (staging == nullptr) {
    return;
  }
  staging->session_reference = nullptr;
  CloseViteSnapshotStaging(staging);
}

void ReleaseViteSnapshotPublishedForEnvironmentCleanup(ViteSnapshotPublished* published) {
  if (published == nullptr) {
    return;
  }
  published->session_reference = nullptr;
  published->pending_staging = nullptr;
  published->commitment_cleanup_pending = false;
  CloseViteSnapshotPublished(published);
}

void ReleaseViteSnapshotSessionForEnvironmentCleanup(ViteSnapshotSession* session) {
  if (session == nullptr || session->closed) {
    return;
  }
  ClearViteSnapshotSessionReferences(session);
  while (!session->stagings.empty()) {
    ViteSnapshotStaging* staging = session->stagings.back();
    if (staging != nullptr) {
      staging->publication_pending = false;
    }
    ReleaseViteSnapshotStagingForEnvironmentCleanup(staging);
  }
  while (!session->published.empty()) {
    ViteSnapshotPublished* published = session->published.back();
    if (published != nullptr) {
      published->commitment_cleanup_pending = false;
      published->pending_staging = nullptr;
    }
    ReleaseViteSnapshotPublishedForEnvironmentCleanup(published);
  }
  (void)CloseViteSnapshotSession(session);
}

void FinalizeViteSnapshotSession(napi_env env, void* data, void*) {
  auto* session = static_cast<ViteSnapshotSession*>(data);
  ViteSnapshotEnvironment* environment = GetViteSnapshotEnvironment(env);
  if (environment == nullptr || environment->cleanup_started ||
      session == nullptr || session->environment != environment) {
    ReleaseViteSnapshotSessionForEnvironmentCleanup(session);
    delete session;
    return;
  }
  if (!CloseViteSnapshotSession(session)) {
    session->finalization_retained = true;
    environment->finalizing_sessions.push_back(session);
    return;
  }
  delete session;
}

void FinalizeViteSnapshotStaging(napi_env env, void* data, void*) {
  auto* staging = static_cast<ViteSnapshotStaging*>(data);
  ViteSnapshotEnvironment* environment = GetViteSnapshotEnvironment(env);
  if (environment == nullptr || environment->cleanup_started || staging == nullptr ||
      staging->env != env || staging->session == nullptr ||
      staging->session->environment != environment) {
    ReleaseViteSnapshotStagingForEnvironmentCleanup(staging);
    delete staging;
    return;
  }
  if (!FinalizeViteSnapshotStaging(staging)) {
    staging->finalization_retained = true;
    environment->finalizing_stagings.push_back(staging);
    return;
  }
  delete staging;
}

void FinalizeViteSnapshotPublished(napi_env env, void* data, void*) {
  auto* published = static_cast<ViteSnapshotPublished*>(data);
  ViteSnapshotEnvironment* environment = GetViteSnapshotEnvironment(env);
  if (environment == nullptr || environment->cleanup_started || published == nullptr ||
      published->env != env || published->session == nullptr ||
      published->session->environment != environment) {
    ReleaseViteSnapshotPublishedForEnvironmentCleanup(published);
    delete published;
    return;
  }
  if (!FinalizeViteSnapshotPublished(published)) {
    published->finalization_retained = true;
    environment->finalizing_published.push_back(published);
    return;
  }
  delete published;
}

bool UnwrapViteSnapshotStaging(napi_env env, napi_value value, ViteSnapshotStaging** output) {
  bool tagged = false;
  if (!GetObject(env, value, &value) ||
      !IsNapiStatusOk(
          napi_check_object_type_tag(env, value, &kViteSnapshotStagingTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr || (*output)->env != env || (*output)->session == nullptr ||
      (*output)->session->environment == nullptr ||
      (*output)->session->environment->env != env ||
      (*output)->session->environment->cleanup_started) {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool RequireViteSnapshotStaging(napi_env env, napi_value value, ViteSnapshotStaging** output) {
  if (!UnwrapViteSnapshotStaging(env, value, output)) {
    return false;
  }
  ViteSnapshotStaging* staging = *output;
  if (staging->closed || staging->published || staging->session == nullptr ||
      !ValidateViteSnapshotSessionAuthority(staging->session)) {
    ThrowSnapshotDenied(env);
    return false;
  }
  const bool linked =
      staging->located_in_published_parent
          ? ValidateSnapshotLinkedDirectory(staging->session->published_parent_fd.Get(),
                                            staging->install_id.c_str(), staging->fd.Get(),
                                            staging->session->owner_uid,
                                            staging->session->root_identity.device,
                                            staging->identity)
          : ValidateSnapshotLinkedDirectory(staging->session->staging_parent_fd.Get(),
                                            staging->name.c_str(), staging->fd.Get(),
                                            staging->session->owner_uid,
                                            staging->session->root_identity.device,
                                            staging->identity);
  if (!linked) {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool UnwrapViteSnapshotPublished(napi_env env, napi_value value, ViteSnapshotPublished** output) {
  bool tagged = false;
  if (!GetObject(env, value, &value) ||
      !IsNapiStatusOk(
          napi_check_object_type_tag(env, value, &kViteSnapshotPublishedTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr || (*output)->env != env || (*output)->session == nullptr ||
      (*output)->session->environment == nullptr ||
      (*output)->session->environment->env != env ||
      (*output)->session->environment->cleanup_started) {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool RequireViteSnapshotPublished(napi_env env, napi_value value, ViteSnapshotPublished** output) {
  if (!UnwrapViteSnapshotPublished(env, value, output)) {
    return false;
  }
  ViteSnapshotPublished* published = *output;
  if (published->closed || published->session == nullptr ||
      !ValidateViteSnapshotSessionAuthority(published->session) ||
      !ValidateSnapshotLinkedDirectory(published->session->published_parent_fd.Get(),
                                       published->install_id.c_str(), published->fd.Get(),
                                       published->session->owner_uid,
                                       published->session->root_identity.device,
                                       published->identity)) {
    ThrowSnapshotDenied(env);
    return false;
  }
  return true;
}

bool WriteAll(int fd, const unsigned char* bytes, size_t length) {
  size_t offset = 0U;
  while (offset < length) {
    const ssize_t written = write(fd, bytes + offset, length - offset);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return false;
    }
    offset += static_cast<size_t>(written);
  }
  return true;
}

bool OpenOrCreateSnapshotChildDirectory(int parent_fd, const std::string& name,
                                        ViteSnapshotSession* session, FileDescriptor* output) {
  if (mkdirat(parent_fd, name.c_str(), 0700) != 0 && errno != EEXIST) {
    return false;
  }
  FileDescriptor child(OpenDirectoryAt(parent_fd, name));
  struct stat stat{};
  if (child.Get() < 0 || fstat(child.Get(), &stat) != 0 ||
      !IsSafeViteSnapshotDirectory(stat, session->owner_uid, session->root_identity.device) ||
      !HasSafeAcl(child.Get())) {
    return false;
  }
  const Identity identity = SnapshotIdentityFromStat(stat);
  if (!ValidateSnapshotLinkedDirectory(parent_fd, name.c_str(), child.Get(), session->owner_uid,
                                       session->root_identity.device, identity) ||
      fsync(parent_fd) != 0) {
    return false;
  }
  *output = std::move(child);
  return true;
}

bool WriteViteSnapshotStagingFile(ViteSnapshotStaging* staging, const std::string& relative_path,
                                  const SensitiveBytes& bytes) {
  std::vector<std::string> components;
  if (relative_path.empty() || relative_path.size() > kMaximumPathBytes ||
      !ParseComponents(staging->env, relative_path, false, &components) || components.empty() ||
      components.size() > kMaximumViteSnapshotDepth) {
    return false;
  }
  const bool generated_package =
      components.size() == 1U && components.front() == "package.json";
  if ((!generated_package && staging->file_count >= kMaximumViteSnapshotFiles) ||
      bytes.Size() > kMaximumViteSnapshotBytes - staging->aggregate_bytes) {
    return false;
  }

  FileDescriptor current(OpenViteCacheDirectoryDescriptor(staging->fd.Get()));
  if (current.Get() < 0) {
    return false;
  }
  for (size_t index = 0; index + 1U < components.size(); ++index) {
    FileDescriptor next;
    if (!OpenOrCreateSnapshotChildDirectory(current.Get(), components[index], staging->session, &next)) {
      return false;
    }
    current = std::move(next);
  }

  FileDescriptor file(openat(current.Get(), components.back().c_str(),
                             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (file.Get() < 0) {
    return false;
  }
  bool complete = false;
  struct stat before{};
  struct stat linked{};
  struct stat retained{};
  const bool retained_identity_captured = fstat(file.Get(), &retained) == 0;
  const Identity retained_identity =
      retained_identity_captured ? SnapshotIdentityFromStat(retained) : Identity{};
  if (fchmod(file.Get(), 0600) == 0 && fstat(file.Get(), &before) == 0 &&
      IsSafeViteSnapshotFile(before, staging->session->owner_uid,
                             staging->session->root_identity.device) &&
      HasSafeAcl(file.Get()) && WriteAll(file.Get(), bytes.Data(), bytes.Size()) &&
      fsync(file.Get()) == 0 && fstat(file.Get(), &before) == 0 &&
      IsSafeViteSnapshotFile(before, staging->session->owner_uid,
                             staging->session->root_identity.device) &&
      HasSafeAcl(file.Get()) &&
      fstatat(current.Get(), components.back().c_str(), &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
      SameSnapshotIdentity(linked, SnapshotIdentityFromStat(before)) && fsync(current.Get()) == 0) {
    complete = true;
  }
  if (!complete) {
    if (retained_identity_captured) {
      (void)RemoveSnapshotRetainedFile(current.Get(), components.back().c_str(), file.Get(),
                                       retained_identity);
    }
    return false;
  }
  if (!generated_package) {
    staging->file_count += 1U;
  }
  staging->aggregate_bytes += bytes.Size();
  return true;
}

struct ViteSnapshotTreeBudget {
  uint32_t entries = 0U;
  uint32_t directories = 0U;
  uint32_t files = 0U;
  uint64_t bytes = 0U;
};

bool ConsumeViteSnapshotEntryBudget(ViteSnapshotTreeBudget* budget) {
  if (budget == nullptr || budget->entries >= kMaximumViteSnapshotEntries) {
    return false;
  }
  budget->entries += 1U;
  return true;
}

bool ConsumeViteSnapshotDirectoryBudget(ViteSnapshotTreeBudget* budget) {
  if (budget == nullptr || budget->directories >= kMaximumViteSnapshotDirectories) {
    return false;
  }
  budget->directories += 1U;
  return true;
}

bool CheckViteSnapshotFileBudget(const struct stat& stat, bool generated_package,
                                 ViteSnapshotTreeBudget* budget) {
  if (budget == nullptr || stat.st_size < 0 ||
      (!generated_package && budget->files >= kMaximumViteSnapshotFiles) ||
      static_cast<uint64_t>(stat.st_size) > kMaximumViteSnapshotBytes - budget->bytes) {
    return false;
  }
  if (!generated_package) {
    budget->files += 1U;
  }
  budget->bytes += static_cast<uint64_t>(stat.st_size);
  return true;
}

bool ValidateViteSnapshotTree(int directory_fd, ViteSnapshotSession* session, uint32_t depth,
                              ViteSnapshotTreeBudget* budget) {
  struct stat directory_stat{};
  if (depth > kMaximumViteSnapshotDepth || fstat(directory_fd, &directory_stat) != 0 ||
      !IsSafeViteSnapshotDirectory(directory_stat, session->owner_uid,
                                   session->root_identity.device) ||
      !HasSafeAcl(directory_fd) || !ConsumeViteSnapshotDirectoryBudget(budget)) {
    return false;
  }
  const int duplicate_fd = OpenViteCacheDirectoryDescriptor(directory_fd);
  if (duplicate_fd < 0) {
    return false;
  }
  DIR* directory = fdopendir(duplicate_fd);
  if (directory == nullptr) {
    (void)close(duplicate_fd);
    return false;
  }

  bool valid = true;
  while (valid) {
    errno = 0;
    struct dirent* entry = readdir(directory);
    if (entry == nullptr) {
      valid = errno == 0;
      break;
    }
    if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    if (!ConsumeViteSnapshotEntryBudget(budget) || depth >= kMaximumViteSnapshotDepth) {
      valid = false;
      break;
    }
    struct stat child{};
    if (fstatat(directory_fd, entry->d_name, &child, AT_SYMLINK_NOFOLLOW) != 0) {
      valid = false;
      break;
    }
    if (S_ISDIR(child.st_mode)) {
      FileDescriptor child_fd(OpenDirectoryAt(directory_fd, entry->d_name));
      if (child_fd.Get() < 0 ||
          !IsSafeViteSnapshotDirectory(child, session->owner_uid,
                                        session->root_identity.device) ||
          !ValidateSnapshotDirectoryFd(child_fd.Get(), session->owner_uid,
                                       session->root_identity.device, SnapshotIdentityFromStat(child)) ||
          !ValidateViteSnapshotTree(child_fd.Get(), session, depth + 1U, budget) ||
          !ValidateSnapshotLinkedDirectory(directory_fd, entry->d_name, child_fd.Get(),
                                           session->owner_uid, session->root_identity.device,
                                           SnapshotIdentityFromStat(child))) {
        valid = false;
        break;
      }
      continue;
    }
    const bool generated_package = depth == 0U && std::strcmp(entry->d_name, "package.json") == 0;
    if (!IsSafeViteSnapshotFile(child, session->owner_uid, session->root_identity.device) ||
        !CheckViteSnapshotFileBudget(child, generated_package, budget)) {
      valid = false;
      break;
    }
    FileDescriptor file(
        openat(directory_fd, entry->d_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    struct stat opened{};
    if (file.Get() < 0 || fstat(file.Get(), &opened) != 0 ||
        !IsSafeViteSnapshotFile(opened, session->owner_uid, session->root_identity.device) ||
        !HasSafeAcl(file.Get()) || !SameSnapshotIdentity(opened, SnapshotIdentityFromStat(child))) {
      valid = false;
      break;
    }
  }
  if (closedir(directory) != 0) {
    valid = false;
  }
  struct stat after{};
  return valid && fstat(directory_fd, &after) == 0 &&
         IsSafeViteSnapshotDirectory(after, session->owner_uid, session->root_identity.device) &&
         HasSafeAcl(directory_fd) && SameSnapshotIdentity(after, SnapshotIdentityFromStat(directory_stat));
}

bool RemoveViteSnapshotTree(int directory_fd, ViteSnapshotSession* session, uint32_t depth,
                            ViteSnapshotTreeBudget* budget) {
  struct stat directory_stat{};
  if (depth > kMaximumViteSnapshotDepth || fstat(directory_fd, &directory_stat) != 0 ||
      !IsSafeViteSnapshotDirectory(directory_stat, session->owner_uid,
                                   session->root_identity.device) ||
      !HasSafeAcl(directory_fd) || !ConsumeViteSnapshotDirectoryBudget(budget)) {
    return false;
  }
  const int duplicate_fd = OpenViteCacheDirectoryDescriptor(directory_fd);
  if (duplicate_fd < 0) {
    return false;
  }
  DIR* directory = fdopendir(duplicate_fd);
  if (directory == nullptr) {
    (void)close(duplicate_fd);
    return false;
  }

  bool valid = true;
  while (valid) {
    errno = 0;
    struct dirent* entry = readdir(directory);
    if (entry == nullptr) {
      valid = errno == 0;
      break;
    }
    if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    if (!ConsumeViteSnapshotEntryBudget(budget) || depth >= kMaximumViteSnapshotDepth) {
      valid = false;
      break;
    }
    struct stat child{};
    if (fstatat(directory_fd, entry->d_name, &child, AT_SYMLINK_NOFOLLOW) != 0) {
      valid = false;
      break;
    }
    if (S_ISDIR(child.st_mode)) {
      FileDescriptor child_fd(OpenDirectoryAt(directory_fd, entry->d_name));
      if (child_fd.Get() < 0 ||
          !IsSafeViteSnapshotDirectory(child, session->owner_uid,
                                        session->root_identity.device) ||
          !ValidateSnapshotDirectoryFd(child_fd.Get(), session->owner_uid,
                                       session->root_identity.device, SnapshotIdentityFromStat(child)) ||
          !RemoveViteSnapshotTree(child_fd.Get(), session, depth + 1U, budget) ||
          !RemoveSnapshotRetainedDirectory(directory_fd, entry->d_name, child_fd.Get(),
                                           session->owner_uid, session->root_identity.device,
                                           SnapshotIdentityFromStat(child))) {
        valid = false;
        break;
      }
      continue;
    }
    const bool generated_package = depth == 0U && std::strcmp(entry->d_name, "package.json") == 0;
    if (!IsSafeViteSnapshotFile(child, session->owner_uid, session->root_identity.device) ||
        !CheckViteSnapshotFileBudget(child, generated_package, budget)) {
      valid = false;
      break;
    }
    FileDescriptor file(
        openat(directory_fd, entry->d_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    struct stat opened{};
    if (file.Get() < 0 || fstat(file.Get(), &opened) != 0 ||
        !IsSafeViteSnapshotFile(opened, session->owner_uid, session->root_identity.device) ||
        !HasSafeAcl(file.Get()) || !SameSnapshotIdentity(opened, SnapshotIdentityFromStat(child)) ||
        !RemoveSnapshotRetainedFile(directory_fd, entry->d_name, file.Get(),
                                    SnapshotIdentityFromStat(opened))) {
      valid = false;
      break;
    }
  }
  if (closedir(directory) != 0) {
    valid = false;
  }
  struct stat after{};
  return valid && fstat(directory_fd, &after) == 0 &&
         IsSafeViteSnapshotDirectory(after, session->owner_uid, session->root_identity.device) &&
         HasSafeAcl(directory_fd) && SameSnapshotIdentity(after, SnapshotIdentityFromStat(directory_stat)) &&
         fsync(directory_fd) == 0;
}

bool RenameViteSnapshotNoReplace(int source_parent_fd, const char* source_name, int target_parent_fd,
                                 const char* target_name) {
#if defined(__APPLE__)
  return renameatx_np(source_parent_fd, source_name, target_parent_fd, target_name, RENAME_EXCL) == 0;
#elif defined(__linux__)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0U)
#endif
  return syscall(SYS_renameat2, source_parent_fd, source_name, target_parent_fd, target_name,
                 RENAME_NOREPLACE) == 0;
#endif
}
bool RollbackViteSnapshotPublication(ViteSnapshotStaging* staging,
                                     const std::string& install_id) {
  if (staging == nullptr || staging->session == nullptr || staging->closed ||
      staging->published || !staging->publication_pending) {
    return false;
  }
  ViteSnapshotSession* session = staging->session;
  if (!ValidateViteSnapshotSessionAuthority(session) ||
      !ValidateSnapshotDirectoryFd(staging->fd.Get(), session->owner_uid,
                                   session->root_identity.device, staging->identity)) {
    return false;
  }
  if (staging->located_in_published_parent) {
    if (!ValidateSnapshotLinkedDirectory(session->published_parent_fd.Get(), install_id.c_str(),
                                         staging->fd.Get(), session->owner_uid,
                                         session->root_identity.device, staging->identity) ||
        !RenameViteSnapshotNoReplace(session->published_parent_fd.Get(), install_id.c_str(),
                                     session->staging_parent_fd.Get(), staging->name.c_str())) {
      return false;
    }
    staging->located_in_published_parent = false;
  } else if (!ValidateSnapshotLinkedDirectory(session->staging_parent_fd.Get(), staging->name.c_str(),
                                              staging->fd.Get(), session->owner_uid,
                                              session->root_identity.device, staging->identity)) {
    return false;
  }
  if (fsync(session->published_parent_fd.Get()) != 0 ||
      fsync(session->staging_parent_fd.Get()) != 0 ||
      !ValidateViteSnapshotSessionAuthority(session) ||
      !ValidateSnapshotLinkedDirectory(session->staging_parent_fd.Get(), staging->name.c_str(),
                                       staging->fd.Get(), session->owner_uid,
                                       session->root_identity.device, staging->identity)) {
    return false;
  }
  staging->publication_pending = false;
  return true;

}
bool ReleaseViteSnapshotStagingAfterPublication(ViteSnapshotStaging* staging) {
  if (staging == nullptr || staging->closed || staging->session == nullptr) {
    return false;
  }
  if (staging->session_reference != nullptr &&
      !IsNapiStatusOk(napi_delete_reference(staging->env, staging->session_reference))) {
    return false;
  }
  staging->session_reference = nullptr;
  staging->published = true;
  staging->publication_pending = false;
  staging->located_in_published_parent = true;
  staging->closed = true;
  staging->fd.Reset();
  RemoveViteSnapshotStaging(staging);
  ZeroizeString(&staging->install_id);
  ZeroizeString(&staging->name);
  if (staging->slot_charged) {
    ReleaseAuthoritySlot(&active_vite_snapshot_stagings);
    staging->slot_charged = false;
  }
  return true;
}

napi_value OpenViteSnapshotSession(napi_env env, napi_callback_info info) {
  ViteSnapshotEnvironment* environment = GetViteSnapshotEnvironment(env);
  if (environment == nullptr || environment->cleanup_started) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  (void)DrainRetainedViteSnapshotFinalizers(env);
  std::string project_root;
  Identity approved_root{};
  uid_t owner_uid = 0;
  if (!ParseViteSnapshotSessionOptions(env, info, &project_root, &approved_root, &owner_uid)) {
    return nullptr;
  }

  FileDescriptor root_parent;
  FileDescriptor root;
  Identity root_parent_identity{};
  std::string root_name;
  std::vector<Identity> canonical_ancestor_identities;
  if (!OpenViteSnapshotRoot(project_root, approved_root, owner_uid, &root_parent, &root,
                            &root_parent_identity, &root_name, &canonical_ancestor_identities)) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  FileDescriptor scene_glass;
  FileDescriptor runtime;
  FileDescriptor vite_cache;
  FileDescriptor staging_parent;
  FileDescriptor published_parent;
  FileDescriptor provenance;
  Identity scene_glass_identity{};
  Identity runtime_identity{};
  Identity vite_cache_identity{};
  Identity staging_parent_identity{};
  Identity published_parent_identity{};
  Identity provenance_identity{};
  if (!OpenOrCreateViteSnapshotDirectory(root.Get(), ".scg", owner_uid, approved_root.device,
                                         &scene_glass, &scene_glass_identity) ||
      !OpenOrCreateViteSnapshotDirectory(scene_glass.Get(), "runtime", owner_uid,
                                         approved_root.device, &runtime, &runtime_identity) ||
      !OpenOrCreateViteSnapshotDirectory(runtime.Get(), "vite-cache", owner_uid,
                                         approved_root.device, &vite_cache,
                                         &vite_cache_identity) ||
      !OpenOrCreateViteSnapshotDirectory(runtime.Get(), "vite-staging", owner_uid,
                                         approved_root.device, &staging_parent,
                                         &staging_parent_identity) ||
      !OpenOrCreateViteSnapshotDirectory(runtime.Get(), "vite-root", owner_uid,
                                         approved_root.device, &published_parent,
                                         &published_parent_identity) ||
      !OpenOrCreateViteSnapshotDirectory(runtime.Get(), "vite-provenance", owner_uid,
                                         approved_root.device, &provenance, &provenance_identity)) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_vite_snapshot_sessions, kMaximumViteSnapshotSessions)) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }

  auto* session = new (std::nothrow) ViteSnapshotSession{
      .environment = environment,
      .root_parent_fd = std::move(root_parent),
      .root_fd = std::move(root),
      .scene_glass_fd = std::move(scene_glass),
      .runtime_fd = std::move(runtime),
      .staging_parent_fd = std::move(staging_parent),
      .published_parent_fd = std::move(published_parent),
      .provenance_fd = std::move(provenance),
      .root_parent_identity = root_parent_identity,
      .root_identity = approved_root,
      .scene_glass_identity = scene_glass_identity,
      .runtime_identity = runtime_identity,
      .staging_parent_identity = staging_parent_identity,
      .published_parent_identity = published_parent_identity,
      .provenance_identity = provenance_identity,
      .root_name = std::move(root_name),
      .canonical_root_path = std::move(project_root),
      .canonical_ancestor_identities = std::move(canonical_ancestor_identities),
      .owner_uid = owner_uid,
      .slot_charged = true,
  };
  if (session == nullptr) {
    ReleaseAuthoritySlot(&active_vite_snapshot_sessions);
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  napi_value session_value;
  if (!IsNapiStatusOk(napi_create_object(env, &session_value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, session_value, &kViteSnapshotSessionTypeTag)) ||
      !IsNapiStatusOk(
          napi_wrap(env, session_value, session, FinalizeViteSnapshotSession, nullptr, nullptr))) {
    CloseViteSnapshotSession(session);
    delete session;
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  return session_value;
}

napi_value CreateViteSnapshotStaging(napi_env env, napi_callback_info info) {
  (void)DrainRetainedViteSnapshotFinalizers(env);
  napi_value session_value;
  Identity approved_root{};
  std::string install_id;
  std::string staging_name;
  if (!ParseViteSnapshotStagingOptions(env, info, &session_value, &approved_root, &install_id,
                                       &staging_name)) {
    return nullptr;
  }
  ViteSnapshotSession* session = nullptr;
  if (!RequireViteSnapshotSession(env, session_value, &session)) {
    return nullptr;
  }
  if (!SameIdentity(approved_root, session->root_identity)) {
    Throw(env, kIdentityMismatchCode, "secure native snapshot identity mismatch");
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_vite_snapshot_stagings, kMaximumViteSnapshotStagings)) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  if (mkdirat(session->staging_parent_fd.Get(), staging_name.c_str(), 0700) != 0) {
    ReleaseAuthoritySlot(&active_vite_snapshot_stagings);
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  FileDescriptor staging_fd(OpenDirectoryAt(session->staging_parent_fd.Get(), staging_name));
  struct stat staging_stat{};
  const bool staging_identity_captured =
      staging_fd.Get() >= 0 && fstat(staging_fd.Get(), &staging_stat) == 0;
  if (!staging_identity_captured ||
      !IsSafeViteSnapshotDirectory(staging_stat, session->owner_uid,
                                   session->root_identity.device) ||
      !HasSafeAcl(staging_fd.Get())) {
    if (staging_identity_captured) {
      (void)RemoveSnapshotRetainedDirectory(session->staging_parent_fd.Get(), staging_name.c_str(),
                                            staging_fd.Get(), session->owner_uid,
                                            session->root_identity.device,
                                            SnapshotIdentityFromStat(staging_stat));
    }
    ReleaseAuthoritySlot(&active_vite_snapshot_stagings);
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  const Identity staging_identity = SnapshotIdentityFromStat(staging_stat);
  if (!ValidateSnapshotLinkedDirectory(session->staging_parent_fd.Get(), staging_name.c_str(),
                                       staging_fd.Get(), session->owner_uid,
                                       session->root_identity.device, staging_identity) ||
      fsync(session->staging_parent_fd.Get()) != 0) {
    (void)RemoveSnapshotRetainedDirectory(session->staging_parent_fd.Get(), staging_name.c_str(),
                                          staging_fd.Get(), session->owner_uid,
                                          session->root_identity.device, staging_identity);
    ReleaseAuthoritySlot(&active_vite_snapshot_stagings);
    ThrowSnapshotDenied(env);
    return nullptr;
  }

  auto* staging = new (std::nothrow) ViteSnapshotStaging{
      .env = env,
      .session = session,
      .fd = std::move(staging_fd),
      .identity = staging_identity,
      .install_id = std::move(install_id),
      .name = std::move(staging_name),
      .slot_charged = true,
  };
  if (staging == nullptr) {
    (void)RemoveSnapshotRetainedDirectory(session->staging_parent_fd.Get(), staging_name.c_str(),
                                          staging_fd.Get(), session->owner_uid,
                                          session->root_identity.device, staging_identity);
    ReleaseAuthoritySlot(&active_vite_snapshot_stagings);
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  napi_value staging_value;
  if (!IsNapiStatusOk(napi_create_object(env, &staging_value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, staging_value, &kViteSnapshotStagingTypeTag)) ||
      !IsNapiStatusOk(napi_create_reference(env, session_value, 1U, &staging->session_reference)) ||
      !IsNapiStatusOk(
          napi_wrap(env, staging_value, staging, FinalizeViteSnapshotStaging, nullptr, nullptr))) {
    (void)RemoveSnapshotRetainedDirectory(session->staging_parent_fd.Get(), staging->name.c_str(),
                                          staging->fd.Get(), session->owner_uid,
                                          session->root_identity.device, staging->identity);
    CloseViteSnapshotStaging(staging);
    delete staging;
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  session->stagings.push_back(staging);
  return staging_value;
}

napi_value WriteViteSnapshotStagingFileBinding(napi_env env, napi_callback_info info) {
  (void)DrainRetainedViteSnapshotFinalizers(env);
  napi_value staging_value;
  std::string relative_path;
  SensitiveBytes bytes(0U);
  if (!ParseViteSnapshotWriteOptions(env, info, &staging_value, &relative_path, &bytes)) {
    return nullptr;
  }
  ViteSnapshotStaging* staging = nullptr;
  if (!RequireViteSnapshotStaging(env, staging_value, &staging)) {
    return nullptr;
  }
  if (staging->publication_pending) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  if (!WriteViteSnapshotStagingFile(staging, relative_path, bytes) ||
      !ValidateViteSnapshotSessionAuthority(staging->session) ||
      !ValidateSnapshotLinkedDirectory(staging->session->staging_parent_fd.Get(),
                                       staging->name.c_str(), staging->fd.Get(),
                                       staging->session->owner_uid,
                                       staging->session->root_identity.device,
                                       staging->identity)) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  return result;
}

napi_value PublishViteSnapshotStaging(napi_env env, napi_callback_info info) {
  (void)DrainRetainedViteSnapshotFinalizers(env);
  napi_value staging_value;
  Identity approved_root{};
  std::string install_id;
  if (!ParseViteSnapshotPublishedOptions(env, info, &staging_value, &approved_root, &install_id)) {
    return nullptr;
  }
  ViteSnapshotStaging* staging = nullptr;
  if (!RequireViteSnapshotStaging(env, staging_value, &staging)) {
    return nullptr;
  }
  ViteSnapshotSession* session = staging->session;
  if (!SameIdentity(approved_root, session->root_identity) || install_id != staging->install_id) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  if (staging->publication_pending) {
    if (!RollbackViteSnapshotPublication(staging, install_id)) {
      ThrowSnapshotDenied(env);
      return nullptr;
    }
    CloseViteSnapshotPendingPublished(staging);
  }
  ViteSnapshotTreeBudget budget{};
  if (!ValidateViteSnapshotTree(staging->fd.Get(), session, 0U, &budget) ||
      !ValidateViteSnapshotSessionAuthority(session) ||
      !ValidateSnapshotLinkedDirectory(session->staging_parent_fd.Get(), staging->name.c_str(),
                                       staging->fd.Get(), session->owner_uid,
                                       session->root_identity.device, staging->identity)) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_vite_snapshot_published, kMaximumViteSnapshotPublished)) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }

  auto* published = new (std::nothrow) ViteSnapshotPublished{
      .env = env,
      .session = session,
      .session_reference = nullptr,
      .fd = FileDescriptor(),
      .identity = staging->identity,
      .install_id = install_id,
      .commitment_fd = FileDescriptor(),
      .pending_staging = staging,
      .slot_charged = true,
  };
  if (published == nullptr) {
    ReleaseAuthoritySlot(&active_vite_snapshot_published);
    ThrowSnapshotFailure(env);
    return nullptr;
  }

  napi_value published_value;
  napi_value retained_session_value;
  napi_value identity;
  napi_value result;
  if (staging->session_reference == nullptr ||
      !IsNapiStatusOk(
          napi_get_reference_value(env, staging->session_reference, &retained_session_value)) ||
      !IsNapiStatusOk(napi_create_object(env, &published_value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, published_value, &kViteSnapshotPublishedTypeTag)) ||
      !IsNapiStatusOk(
          napi_create_reference(env, retained_session_value, 1U, &published->session_reference))) {
    CloseViteSnapshotPublished(published);
    delete published;
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  if (!IsNapiStatusOk(
          napi_wrap(env, published_value, published, FinalizeViteSnapshotPublished, nullptr, nullptr))) {
    CloseViteSnapshotPublished(published);
    delete published;
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  if (!CreateViteCacheIdentity(env, staging->identity, &identity) ||
      !IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "published", published_value)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "rootIdentity", identity))) {
    CloseViteSnapshotPublished(published);
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  session->published.push_back(published);

  if (!RenameViteSnapshotNoReplace(session->staging_parent_fd.Get(), staging->name.c_str(),
                                   session->published_parent_fd.Get(), install_id.c_str())) {
    CloseViteSnapshotPendingPublished(staging);
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  staging->located_in_published_parent = true;
  staging->publication_pending = true;
  if (fsync(session->staging_parent_fd.Get()) != 0 || fsync(session->published_parent_fd.Get()) != 0) {
    if (RollbackViteSnapshotPublication(staging, install_id)) {
      CloseViteSnapshotPendingPublished(staging);
    }
    ThrowSnapshotDenied(env);
    return nullptr;
  }

  FileDescriptor published_fd(OpenDirectoryAt(session->published_parent_fd.Get(), install_id));
  struct stat published_stat{};
  if (published_fd.Get() < 0 || fstat(published_fd.Get(), &published_stat) != 0 ||
      !IsSafeViteSnapshotDirectory(published_stat, session->owner_uid,
                                   session->root_identity.device) ||
      !SameSnapshotIdentity(published_stat, staging->identity) || !HasSafeAcl(published_fd.Get()) ||
      !ValidateSnapshotLinkedDirectory(session->published_parent_fd.Get(), install_id.c_str(),
                                       published_fd.Get(), session->owner_uid,
                                       session->root_identity.device, staging->identity)) {
    if (RollbackViteSnapshotPublication(staging, install_id)) {
      CloseViteSnapshotPendingPublished(staging);
    }
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  published->fd = std::move(published_fd);
  if (!ReleaseViteSnapshotStagingAfterPublication(staging)) {
    if (RollbackViteSnapshotPublication(staging, install_id)) {
      CloseViteSnapshotPendingPublished(staging);
    }
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  published->pending_staging = nullptr;
  return result;
}

bool ClearPendingViteSnapshotCommitment(ViteSnapshotPublished* published) {
  if (published == nullptr || !published->commitment_cleanup_pending ||
      published->session == nullptr || published->commitment_name.empty()) {
    return published != nullptr && !published->commitment_cleanup_pending;
  }
  ViteSnapshotSession* session = published->session;
  if (!published->commitment_unlinked) {
    if (!ValidateViteSnapshotSessionAuthority(session) ||
        !RemoveSnapshotRetainedFile(session->provenance_fd.Get(), published->commitment_name.c_str(),
                                    published->commitment_fd.Get(), published->commitment_identity)) {
      return false;
    }
    published->commitment_unlinked = true;
  }
  if (fsync(session->provenance_fd.Get()) != 0) {
    return false;
  }
  published->commitment_fd.Reset();
  published->commitment_identity = Identity{};
  published->commitment_cleanup_pending = false;
  published->commitment_unlinked = false;
  ZeroizeString(&published->commitment_name);
  return true;
}

napi_value PersistViteSnapshotCommitment(napi_env env, napi_callback_info info) {
  (void)DrainRetainedViteSnapshotFinalizers(env);
  napi_value published_value;
  std::string install_id;
  SensitiveBytes bytes(0U);
  if (!ParseViteSnapshotCommitmentOptions(env, info, &published_value, &install_id, &bytes)) {
    return nullptr;
  }
  ViteSnapshotPublished* published = nullptr;
  if (!RequireViteSnapshotPublished(env, published_value, &published)) {
    return nullptr;
  }
  ViteSnapshotSession* session = published->session;
  if (install_id != published->install_id || !ClearPendingViteSnapshotCommitment(published)) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }

  const std::string filename = install_id + ".json";
  const std::string temporary_name = "." + filename + ".tmp";
  FileDescriptor commitment(openat(session->provenance_fd.Get(), temporary_name.c_str(),
                                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  struct stat retained{};
  if (commitment.Get() < 0 || fstat(commitment.Get(), &retained) != 0) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  published->commitment_fd = std::move(commitment);
  published->commitment_identity = SnapshotIdentityFromStat(retained);
  published->commitment_name = temporary_name;
  published->commitment_cleanup_pending = true;
  published->commitment_unlinked = false;

  struct stat stat{};
  struct stat linked{};
  bool committed = fchmod(published->commitment_fd.Get(), 0600) == 0 &&
                   fstat(published->commitment_fd.Get(), &stat) == 0 &&
                   IsSafeViteSnapshotFile(stat, session->owner_uid, session->root_identity.device) &&
                   HasSafeAcl(published->commitment_fd.Get()) &&
                   WriteAll(published->commitment_fd.Get(), bytes.Data(), bytes.Size()) &&
                   fsync(published->commitment_fd.Get()) == 0 &&
                   fstat(published->commitment_fd.Get(), &stat) == 0 &&
                   IsSafeViteSnapshotFile(stat, session->owner_uid, session->root_identity.device) &&
                   HasSafeAcl(published->commitment_fd.Get()) &&
                   fstatat(session->provenance_fd.Get(), temporary_name.c_str(), &linked,
                           AT_SYMLINK_NOFOLLOW) == 0 &&
                   SameSnapshotIdentity(linked, published->commitment_identity) &&
                   RenameViteSnapshotNoReplace(session->provenance_fd.Get(), temporary_name.c_str(),
                                               session->provenance_fd.Get(), filename.c_str());
  if (committed) {
    published->commitment_name = filename;
    committed = fsync(session->provenance_fd.Get()) == 0 &&
                ValidateViteSnapshotSessionAuthority(session) &&
                ValidateSnapshotLinkedDirectory(session->published_parent_fd.Get(),
                                                published->install_id.c_str(), published->fd.Get(),
                                                session->owner_uid, session->root_identity.device,
                                                published->identity);
  }
  if (!committed) {
    (void)ClearPendingViteSnapshotCommitment(published);
    ThrowSnapshotDenied(env);
    return nullptr;
  }

  published->commitment_fd.Reset();
  published->commitment_identity = Identity{};
  published->commitment_cleanup_pending = false;
  published->commitment_unlinked = false;
  ZeroizeString(&published->commitment_name);
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  return result;
}

bool RemoveViteSnapshotStagingDirectory(ViteSnapshotStaging* staging) {
  ViteSnapshotSession* session = staging->session;
  ViteSnapshotTreeBudget budget{};
  return RemoveViteSnapshotTree(staging->fd.Get(), session, 0U, &budget) &&
         RemoveSnapshotRetainedDirectory(session->staging_parent_fd.Get(), staging->name.c_str(),
                                         staging->fd.Get(), session->owner_uid,
                                         session->root_identity.device, staging->identity) &&
         fsync(session->staging_parent_fd.Get()) == 0;
}

bool RemoveViteSnapshotPublishedDirectory(ViteSnapshotPublished* published) {
  ViteSnapshotSession* session = published->session;
  ViteSnapshotTreeBudget budget{};
  return ClearPendingViteSnapshotCommitment(published) &&
         RemoveViteSnapshotTree(published->fd.Get(), session, 0U, &budget) &&
         RemoveSnapshotRetainedDirectory(session->published_parent_fd.Get(),
                                         published->install_id.c_str(), published->fd.Get(),
                                         session->owner_uid, session->root_identity.device,
                                         published->identity) &&
         fsync(session->published_parent_fd.Get()) == 0;
}

bool FinalizeViteSnapshotStaging(ViteSnapshotStaging* staging) {
  if (staging == nullptr || staging->closed) {
    return true;
  }
  if (staging->session == nullptr) {
    return false;
  }
  if (staging->publication_pending) {
    if (!RollbackViteSnapshotPublication(staging, staging->install_id)) {
      return false;
    }
    CloseViteSnapshotPendingPublished(staging);
  }
  if (!staging->published && !RemoveViteSnapshotStagingDirectory(staging)) {
    return false;
  }
  CloseViteSnapshotStaging(staging);
  return staging->closed;
}

bool FinalizeViteSnapshotPublished(ViteSnapshotPublished* published) {
  if (published == nullptr || published->closed) {
    return true;
  }
  if (published->session == nullptr) {
    return false;
  }
  if (published->pending_staging != nullptr) {
    ViteSnapshotStaging* staging = published->pending_staging;
    if (staging->publication_pending &&
        !RollbackViteSnapshotPublication(staging, staging->install_id)) {
      return false;
    }
    published->pending_staging = nullptr;
    CloseViteSnapshotPublished(published);
    return published->closed;
  }
  if (!RemoveViteSnapshotPublishedDirectory(published)) {
    return false;
  }
  CloseViteSnapshotPublished(published);
  return published->closed;
}

bool DrainRetainedViteSnapshotFinalizers(napi_env env) {
  ViteSnapshotEnvironment* environment = GetViteSnapshotEnvironment(env);
  if (environment == nullptr || environment->cleanup_started) {
    return false;
  }

  bool complete = true;
  for (auto iterator = environment->finalizing_stagings.begin();
       iterator != environment->finalizing_stagings.end();) {
    ViteSnapshotStaging* staging = *iterator;
    if (staging == nullptr || staging->env != env || staging->session == nullptr ||
        staging->session->environment != environment) {
      complete = false;
      iterator = environment->finalizing_stagings.erase(iterator);
      ReleaseViteSnapshotStagingForEnvironmentCleanup(staging);
      delete staging;
      continue;
    }
    if (!FinalizeViteSnapshotStaging(staging)) {
      complete = false;
      ++iterator;
      continue;
    }
    iterator = environment->finalizing_stagings.erase(iterator);
    delete staging;
  }
  for (auto iterator = environment->finalizing_published.begin();
       iterator != environment->finalizing_published.end();) {
    ViteSnapshotPublished* published = *iterator;
    if (published == nullptr || published->env != env || published->session == nullptr ||
        published->session->environment != environment) {
      complete = false;
      iterator = environment->finalizing_published.erase(iterator);
      ReleaseViteSnapshotPublishedForEnvironmentCleanup(published);
      delete published;
      continue;
    }
    if (!FinalizeViteSnapshotPublished(published)) {
      complete = false;
      ++iterator;
      continue;
    }
    iterator = environment->finalizing_published.erase(iterator);
    delete published;
  }
  for (auto iterator = environment->finalizing_sessions.begin();
       iterator != environment->finalizing_sessions.end();) {
    ViteSnapshotSession* session = *iterator;
    if (session == nullptr || session->environment != environment) {
      complete = false;
      iterator = environment->finalizing_sessions.erase(iterator);
      ReleaseViteSnapshotSessionForEnvironmentCleanup(session);
      delete session;
      continue;
    }
    if (!CloseViteSnapshotSession(session)) {
      complete = false;
      ++iterator;
      continue;
    }
    iterator = environment->finalizing_sessions.erase(iterator);
    delete session;
  }
  return complete;
}

void CleanupViteSnapshotEnvironment(void* data) {
  auto* environment = static_cast<ViteSnapshotEnvironment*>(data);
  if (environment == nullptr || environment->cleanup_started) {
    return;
  }
  environment->cleanup_started = true;

  for (ViteSnapshotStaging* staging : environment->finalizing_stagings) {
    if (staging != nullptr) {
      ClearViteSnapshotSessionReferences(staging->session);
      staging->session_reference = nullptr;
    }
  }
  for (ViteSnapshotPublished* published : environment->finalizing_published) {
    if (published != nullptr) {
      ClearViteSnapshotSessionReferences(published->session);
      published->session_reference = nullptr;
    }
  }
  for (ViteSnapshotSession* session : environment->finalizing_sessions) {
    ClearViteSnapshotSessionReferences(session);
  }

  while (!environment->finalizing_stagings.empty()) {
    ViteSnapshotStaging* staging = environment->finalizing_stagings.back();
    environment->finalizing_stagings.pop_back();
    if (staging != nullptr && !FinalizeViteSnapshotStaging(staging)) {
      ReleaseViteSnapshotStagingForEnvironmentCleanup(staging);
    }
    delete staging;
  }
  while (!environment->finalizing_published.empty()) {
    ViteSnapshotPublished* published = environment->finalizing_published.back();
    environment->finalizing_published.pop_back();
    if (published != nullptr && !FinalizeViteSnapshotPublished(published)) {
      ReleaseViteSnapshotPublishedForEnvironmentCleanup(published);
    }
    delete published;
  }
  while (!environment->finalizing_sessions.empty()) {
    ViteSnapshotSession* session = environment->finalizing_sessions.back();
    environment->finalizing_sessions.pop_back();
    if (session != nullptr && !CloseViteSnapshotSession(session)) {
      ReleaseViteSnapshotSessionForEnvironmentCleanup(session);
    }
    delete session;
  }
}

napi_value DiscardViteSnapshotStaging(napi_env env, napi_callback_info info) {
  (void)DrainRetainedViteSnapshotFinalizers(env);
  napi_value staging_value;
  if (!ParseSingleViteSnapshotHandleOption(env, info, "staging", &staging_value)) {
    return nullptr;
  }
  ViteSnapshotStaging* staging = nullptr;
  if (!RequireViteSnapshotStaging(env, staging_value, &staging)) {
    return nullptr;
  }
  if (staging->publication_pending) {
    if (!RollbackViteSnapshotPublication(staging, staging->install_id)) {
      ThrowSnapshotDenied(env);
      return nullptr;
    }
    CloseViteSnapshotPendingPublished(staging);
  }
  if (!RemoveViteSnapshotStagingDirectory(staging) ||
      !ValidateViteSnapshotSessionAuthority(staging->session)) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  CloseViteSnapshotStaging(staging);
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  return result;
}

napi_value RemoveViteSnapshotPublished(napi_env env, napi_callback_info info) {
  (void)DrainRetainedViteSnapshotFinalizers(env);
  napi_value published_value;
  if (!ParseSingleViteSnapshotHandleOption(env, info, "published", &published_value)) {
    return nullptr;
  }
  ViteSnapshotPublished* published = nullptr;
  if (!RequireViteSnapshotPublished(env, published_value, &published)) {
    return nullptr;
  }
  if (!RemoveViteSnapshotPublishedDirectory(published) ||
      !ValidateViteSnapshotSessionAuthority(published->session)) {
    ThrowSnapshotDenied(env);
    return nullptr;
  }
  CloseViteSnapshotPublished(published);
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  return result;
}

napi_value CloseViteSnapshotSessionBinding(napi_env env, napi_callback_info info) {
  (void)DrainRetainedViteSnapshotFinalizers(env);
  napi_value session_value;
  if (!ParseSingleViteSnapshotHandleOption(env, info, "session", &session_value)) {
    return nullptr;
  }
  ViteSnapshotSession* session = nullptr;
  if (!UnwrapViteSnapshotSession(env, session_value, &session)) {
    return nullptr;
  }
  if (!CloseViteSnapshotSession(session)) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowSnapshotFailure(env);
    return nullptr;
  }
  return result;
}
constexpr uint32_t kMaximumViteRecoveryManifestBytes = 512U;
constexpr uint32_t kMaximumViteRecoveryDirectorySessions = 16U;
constexpr uint32_t kMaximumViteRecoveryChildAuthorities = 8U;
std::atomic<uint32_t> active_vite_recovery_directory_sessions{0U};
std::atomic<uint32_t> active_vite_recovery_child_authorities_count{0U};
const napi_type_tag kViteRecoveryDirectorySessionTypeTag = {
    0x1e61dc65398d3e7cULL, 0x8aa69a0b7bf8f173ULL};
const napi_type_tag kManagedViteChildLaunchAuthorityTypeTag = {
    0x50e7b1a054ca1a50ULL, 0xad60d915e5a71bceULL};

struct ViteRecoveryChildAuthority;

struct ViteRecoveryDirectorySession {
  FileDescriptor project_parent_fd;
  FileDescriptor project_fd;
  FileDescriptor scene_glass_fd;
  FileDescriptor runtime_fd;
  FileDescriptor directory_fd;
  FileDescriptor lock_fd;
  Identity project_parent_identity;
  Identity project_identity;
  Identity scene_glass_identity;
  Identity runtime_identity;
  Identity directory_identity;
  Identity lock_identity;
  uid_t owner_uid;
  std::string project_name;
  std::string canonical_project_root;
  std::vector<Identity> canonical_project_ancestor_identities;
  std::string lock_name;
  bool lock_held = false;
  bool closed = false;
  bool slot_charged = false;
  bool finalization_retained = false;
  std::vector<ViteRecoveryChildAuthority*> child_authorities;
};

struct ViteRecoveryChildAuthority {
  FileDescriptor fd;
  int issued_fd = -1;
  ViteRecoveryDirectorySession* session;
  Identity identity;
  std::string install_id;
  std::string launch_id;
  bool launch_binding_cleared = false;
  bool slot_charged = false;
};

struct ManagedViteChildLaunchAuthority {
  FileDescriptor fd;
  Identity state_root_identity;
  uid_t owner_uid;
  std::string install_id;
  std::string launch_id;
  bool released = false;
};

std::vector<ViteRecoveryChildAuthority*> active_vite_recovery_child_authorities;
std::vector<ViteRecoveryDirectorySession*> finalizing_vite_recovery_directory_sessions;
ManagedViteChildLaunchAuthority* active_managed_vite_child_launch_authority = nullptr;

void ThrowRecoveryDenied(napi_env env) {
  Throw(env, kPathDeniedCode, "secure native recovery operation denied");
}

void ThrowRecoveryFailure(napi_env env) {
  Throw(env, kNativeFailureCode, "secure native recovery operation failed");
}

bool IsSafeViteRecoveryDirectory(const struct stat& stat, uid_t owner_uid) {
  return S_ISDIR(stat.st_mode) && stat.st_uid == owner_uid &&
         static_cast<mode_t>(stat.st_mode & 07777) == 0700U;
}

bool IsSafeViteRecoveryFile(const struct stat& stat, uid_t owner_uid) {
  return S_ISREG(stat.st_mode) && stat.st_nlink == 1 && stat.st_size >= 0 &&
         stat.st_uid == owner_uid && static_cast<mode_t>(stat.st_mode & 07777) == 0600U;
}

Identity RecoveryIdentityFromStat(const struct stat& stat) {
  return Identity{static_cast<uint64_t>(stat.st_dev), static_cast<uint64_t>(stat.st_ino)};
}

bool IsViteRecoveryName(const std::string& name, const char* suffix) {
  const std::string ending(suffix);
  if (name.size() <= ending.size() || name.compare(name.size() - ending.size(), ending.size(), ending) != 0) {
    return false;
  }
  return IsViteCacheInstallId(name.substr(0U, name.size() - ending.size()));
}

bool IsViteRecoveryTemporaryName(const std::string& name) {
  if (name.size() < 16U || name.front() != '.' ||
      name.compare(name.size() - 4U, 4U, ".tmp") != 0) {
    return false;
  }
  const size_t recovery = name.find(".recovery.");
  if (recovery == std::string::npos || recovery <= 1U || recovery + 10U >= name.size() - 4U ||
      !IsViteCacheInstallId(name.substr(1U, recovery - 1U))) {
    return false;
  }
  const std::string uuid = name.substr(recovery + 10U, name.size() - recovery - 14U);
  if (uuid.size() != 36U) {
    return false;
  }
  for (size_t index = 0; index < uuid.size(); ++index) {
    const char value = uuid[index];
    if ((index == 8U || index == 13U || index == 18U || index == 23U) ? value != '-'
                                                                         : !((value >= '0' && value <= '9') ||
                                                                             (value >= 'a' && value <= 'f'))) {
      return false;
    }
  }
  return true;
}
bool IsViteRecoveryLaunchId(const std::string& value) {
  if (value.size() != 36U) {
    return false;
  }
  for (size_t index = 0; index < value.size(); ++index) {
    const char character = value[index];
    if ((index == 8U || index == 13U || index == 18U || index == 23U) ? character != '-'
                                                                         : !((character >= '0' && character <= '9') ||
                                                                             (character >= 'a' && character <= 'f'))) {
      return false;
    }
  }
  return true;
}
constexpr const char* kManagedViteChildLaunchAttribute =
#if defined(__APPLE__)
    "com.scene-glass.managed-vite-child-launch";
#else
    "user.scene-glass.managed-vite-child-launch";
#endif

std::string ManagedViteChildLaunchBinding(pid_t issuer_pid, const std::string& install_id,
                                          const std::string& launch_id) {
  return std::to_string(static_cast<long long>(issuer_pid)) + "\n" + install_id + "\n" + launch_id;
}

bool SetManagedViteChildLaunchBinding(int fd, const std::string& install_id,
                                      const std::string& launch_id) {
  const std::string binding = ManagedViteChildLaunchBinding(getpid(), install_id, launch_id);
#if defined(__APPLE__)
  return fsetxattr(fd, kManagedViteChildLaunchAttribute, const_cast<char*>(binding.data()),
                   binding.size(), 0, 0) == 0;
#else
  return fsetxattr(fd, kManagedViteChildLaunchAttribute, binding.data(), binding.size(), 0) == 0;
#endif
}

bool MatchesManagedViteChildLaunchBinding(int fd, pid_t issuer_pid, const std::string& install_id,
                                          const std::string& launch_id) {
  const std::string expected = ManagedViteChildLaunchBinding(issuer_pid, install_id, launch_id);
  std::array<char, 186U> actual{};
#if defined(__APPLE__)
  const ssize_t length =
      fgetxattr(fd, kManagedViteChildLaunchAttribute, actual.data(), actual.size(), 0, 0);
#else
  const ssize_t length =
      fgetxattr(fd, kManagedViteChildLaunchAttribute, actual.data(), actual.size());
#endif
  return length == static_cast<ssize_t>(expected.size()) &&
         std::memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

bool ClearManagedViteChildLaunchBinding(int fd, const std::string& install_id,
                                        const std::string& launch_id) {
  if (!MatchesManagedViteChildLaunchBinding(fd, getpid(), install_id, launch_id)) {
    return false;
  }
#if defined(__APPLE__)
  return fremovexattr(fd, kManagedViteChildLaunchAttribute, 0) == 0;
#else
  return fremovexattr(fd, kManagedViteChildLaunchAttribute) == 0;
#endif
}

bool RecoveryInstallIdFromLockName(const std::string& lock_name, std::string* install_id) {
  constexpr const char* kLockSuffix = ".recovery.v1.lock";
  const size_t suffix_length = std::strlen(kLockSuffix);
  if (lock_name.size() <= suffix_length ||
      lock_name.compare(lock_name.size() - suffix_length, suffix_length, kLockSuffix) != 0) {
    return false;
  }
  const std::string parsed = lock_name.substr(0U, lock_name.size() - suffix_length);
  if (!IsViteCacheInstallId(parsed)) {
    return false;
  }
  *install_id = parsed;
  return true;
}

bool ValidateRecoveryDirectorySession(ViteRecoveryDirectorySession* session) {
  if (session == nullptr || session->closed || session->project_parent_fd.Get() < 0 ||
      session->project_fd.Get() < 0 || session->scene_glass_fd.Get() < 0 ||
      session->directory_fd.Get() < 0 ||
      !ValidateViteSnapshotCanonicalAncestorChain(
          session->canonical_project_root, session->canonical_project_ancestor_identities)) {
    return false;
  }
  struct stat project_parent_stat{};
  if (fstat(session->project_parent_fd.Get(), &project_parent_stat) != 0 ||
      !S_ISDIR(project_parent_stat.st_mode) ||
      !SameIdentity(project_parent_stat, session->project_parent_identity) ||
      !ValidateSnapshotLinkedProjectRoot(session->project_parent_fd.Get(),
                                         session->project_name.c_str(), session->project_fd.Get(),
                                         session->owner_uid, session->project_identity.device,
                                         session->project_identity) ||
      !ValidateSnapshotLinkedDirectory(session->project_fd.Get(), ".scg",
                                       session->scene_glass_fd.Get(), session->owner_uid,
                                       session->project_identity.device,
                                       session->scene_glass_identity) ||
      !ValidateSnapshotLinkedDirectory(session->scene_glass_fd.Get(), "runtime",
                                       session->runtime_fd.Get(), session->owner_uid,
                                       session->project_identity.device, session->runtime_identity) ||
      !ValidateSnapshotLinkedDirectory(session->runtime_fd.Get(), "vite-cache",
                                       session->directory_fd.Get(), session->owner_uid,
                                       session->project_identity.device,
                                       session->directory_identity)) {
    return false;
  }
  if (session->lock_fd.Get() < 0) {
    return session->lock_name.empty() && !session->lock_held;
  }
  struct stat lock_stat{};
  struct stat linked_lock{};
  return session->lock_held && !session->lock_name.empty() &&
         fstat(session->lock_fd.Get(), &lock_stat) == 0 &&
         fstatat(session->directory_fd.Get(), session->lock_name.c_str(), &linked_lock,
                 AT_SYMLINK_NOFOLLOW) == 0 &&
         IsSafeViteRecoveryFile(lock_stat, session->owner_uid) &&
         IsSafeViteRecoveryFile(linked_lock, session->owner_uid) &&
         HasSafeAcl(session->lock_fd.Get()) && SameIdentity(lock_stat, session->lock_identity) &&
         SameIdentity(linked_lock, session->lock_identity);
}

bool RequireViteRecoveryLock(ViteRecoveryDirectorySession* session) {
  return ValidateRecoveryDirectorySession(session) && session->lock_fd.Get() >= 0 &&
         session->lock_held;
}

bool OpenViteRecoveryDirectory(const std::string& project_root,
                               const Identity& expected_project_identity,
                               const std::string& state_root,
                               const Identity& expected_state_identity, uid_t owner_uid,
                               FileDescriptor* project_parent_output, FileDescriptor* project_output,
                               FileDescriptor* scene_glass_output, FileDescriptor* runtime_output,
                               FileDescriptor* state_output,
                               Identity* project_parent_identity_output,
                               Identity* scene_glass_identity_output,
                               Identity* runtime_identity_output, std::string* project_name_output,
                               std::vector<Identity>* project_ancestor_identities_output) {
  const std::string expected_state_root =
      project_root == "/" ? "/.scg/runtime/vite-cache" : project_root + "/.scg/runtime/vite-cache";
  if (project_ancestor_identities_output == nullptr || state_root != expected_state_root ||
      expected_state_identity.device != expected_project_identity.device) {
    return false;
  }

  FileDescriptor project_parent;
  FileDescriptor project;
  Identity project_parent_identity{};
  std::string project_name;
  std::vector<Identity> project_ancestor_identities;
  if (!OpenViteSnapshotRoot(project_root, expected_project_identity, owner_uid, &project_parent,
                            &project, &project_parent_identity, &project_name,
                            &project_ancestor_identities)) {
    return false;
  }

  FileDescriptor scene_glass(OpenDirectoryAt(project.Get(), ".scg"));
  struct stat scene_linked{};
  struct stat scene_stat{};
  if (scene_glass.Get() < 0 ||
      fstatat(project.Get(), ".scg", &scene_linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      fstat(scene_glass.Get(), &scene_stat) != 0 ||
      !IsSafeViteRecoveryDirectory(scene_linked, owner_uid) ||
      !IsSafeViteRecoveryDirectory(scene_stat, owner_uid) || !HasSafeAcl(scene_glass.Get()) ||
      !SameIdentity(scene_linked, RecoveryIdentityFromStat(scene_stat))) {
    return false;
  }
  const Identity scene_glass_identity = RecoveryIdentityFromStat(scene_stat);

  FileDescriptor runtime(OpenDirectoryAt(scene_glass.Get(), "runtime"));
  struct stat runtime_linked{};
  struct stat runtime_stat{};
  if (runtime.Get() < 0 ||
      fstatat(scene_glass.Get(), "runtime", &runtime_linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      fstat(runtime.Get(), &runtime_stat) != 0 ||
      !IsSafeViteRecoveryDirectory(runtime_linked, owner_uid) ||
      !IsSafeViteRecoveryDirectory(runtime_stat, owner_uid) || !HasSafeAcl(runtime.Get()) ||
      !SameIdentity(runtime_linked, RecoveryIdentityFromStat(runtime_stat))) {
    return false;
  }
  const Identity runtime_identity = RecoveryIdentityFromStat(runtime_stat);

  FileDescriptor state(OpenDirectoryAt(runtime.Get(), "vite-cache"));
  struct stat state_linked{};
  struct stat state_stat{};
  if (state.Get() < 0 ||
      fstatat(runtime.Get(), "vite-cache", &state_linked, AT_SYMLINK_NOFOLLOW) != 0 ||
      fstat(state.Get(), &state_stat) != 0 ||
      !IsSafeViteRecoveryDirectory(state_linked, owner_uid) ||
      !IsSafeViteRecoveryDirectory(state_stat, owner_uid) || !HasSafeAcl(state.Get()) ||
      !SameIdentity(state_linked, expected_state_identity) ||
      !SameIdentity(state_stat, expected_state_identity)) {
    return false;
  }
  *project_parent_output = std::move(project_parent);
  *project_output = std::move(project);
  *scene_glass_output = std::move(scene_glass);
  *runtime_output = std::move(runtime);
  *state_output = std::move(state);
  *project_parent_identity_output = project_parent_identity;
  *scene_glass_identity_output = scene_glass_identity;
  *runtime_identity_output = runtime_identity;
  *project_name_output = std::move(project_name);
  *project_ancestor_identities_output = std::move(project_ancestor_identities);
  return true;
}

bool ValidateRecoveryLinkedFile(int directory_fd, const char* name, int file_fd, uid_t owner_uid,
                                const Identity& identity) {
  struct stat linked{};
  struct stat opened{};
  return fstatat(directory_fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0 &&
         fstat(file_fd, &opened) == 0 && IsSafeViteRecoveryFile(linked, owner_uid) &&
         IsSafeViteRecoveryFile(opened, owner_uid) && HasSafeAcl(file_fd) &&
         SameIdentity(linked, identity) && SameIdentity(opened, identity);
}
bool CloseRecoveryFileDescriptor(FileDescriptor* descriptor);


bool CloseRecoveryFileDescriptor(FileDescriptor* descriptor) {
  if (descriptor == nullptr || descriptor->Get() < 0) {
    return true;
  }
  if (close(descriptor->Get()) != 0) {
    return false;
  }
  (void)descriptor->Release();
  return true;
}
bool ValidateManagedViteChildLaunchAuthority(int fd, const Identity& expected_state_root_identity,
                                             uid_t owner_uid, const std::string& install_id,
                                             const std::string& launch_id) {
  struct stat state_root{};
  return fd >= 0 && fstat(fd, &state_root) == 0 &&
         IsSafeViteRecoveryDirectory(state_root, owner_uid) && HasSafeAcl(fd) &&
         SameIdentity(state_root, expected_state_root_identity) &&
         MatchesManagedViteChildLaunchBinding(fd, getppid(), install_id, launch_id) &&
         flock(fd, LOCK_EX | LOCK_NB) == 0;
}

bool CloseManagedViteChildLaunchAuthority(ManagedViteChildLaunchAuthority* authority) {
  if (authority == nullptr || authority->released ||
      !CloseRecoveryFileDescriptor(&authority->fd)) {
    return false;
  }
  authority->released = true;
  if (active_managed_vite_child_launch_authority == authority) {
    active_managed_vite_child_launch_authority = nullptr;
  }
  ZeroizeString(&authority->install_id);
  ZeroizeString(&authority->launch_id);
  return true;
}

void FinalizeManagedViteChildLaunchAuthority(napi_env, void* data, void*) {
  auto* authority = static_cast<ManagedViteChildLaunchAuthority*>(data);
  if (!CloseManagedViteChildLaunchAuthority(authority)) {
    return;
  }
  delete authority;
}

bool UnwrapManagedViteChildLaunchAuthority(napi_env env, napi_value value,
                                           ManagedViteChildLaunchAuthority** output) {
  bool tagged = false;
  if (!GetObject(env, value, &value) ||
      !IsNapiStatusOk(napi_check_object_type_tag(
          env, value, &kManagedViteChildLaunchAuthorityTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}
void RemoveViteRecoveryChildAuthority(ViteRecoveryChildAuthority* authority) {
  if (authority == nullptr) {
    return;
  }
  const auto active = std::find(active_vite_recovery_child_authorities.begin(),
                                active_vite_recovery_child_authorities.end(), authority);
  if (active != active_vite_recovery_child_authorities.end()) {
    active_vite_recovery_child_authorities.erase(active);
  }
  if (authority->session != nullptr) {
    std::vector<ViteRecoveryChildAuthority*>& values = authority->session->child_authorities;
    const auto owned = std::find(values.begin(), values.end(), authority);
    if (owned != values.end()) {
      values.erase(owned);
    }
  }
}

bool CloseViteRecoveryDirectorySession(ViteRecoveryDirectorySession* session);
bool CloseViteRecoveryChildAuthority(ViteRecoveryChildAuthority* authority) {
  if (authority == nullptr || authority->session == nullptr) {
    return false;
  }
  if (!authority->launch_binding_cleared) {
    if (!ClearManagedViteChildLaunchBinding(authority->fd.Get(), authority->install_id,
                                            authority->launch_id)) {
      return false;
    }
    authority->launch_binding_cleared = true;
  }
  if (fsync(authority->fd.Get()) != 0 || !CloseRecoveryFileDescriptor(&authority->fd)) {
    return false;
  }
  ViteRecoveryDirectorySession* session = authority->session;
  RemoveViteRecoveryChildAuthority(authority);
  ZeroizeString(&authority->install_id);
  ZeroizeString(&authority->launch_id);
  if (authority->slot_charged) {
    ReleaseAuthoritySlot(&active_vite_recovery_child_authorities_count);
    authority->slot_charged = false;
  }
  delete authority;
  if (session->finalization_retained && session->child_authorities.empty() &&
      CloseViteRecoveryDirectorySession(session)) {
    const auto retained =
        std::find(finalizing_vite_recovery_directory_sessions.begin(),
                  finalizing_vite_recovery_directory_sessions.end(), session);
    if (retained != finalizing_vite_recovery_directory_sessions.end()) {
      finalizing_vite_recovery_directory_sessions.erase(retained);
    }
    delete session;
  }
  return true;
}

bool CloseViteRecoveryDirectorySession(ViteRecoveryDirectorySession* session) {
  if (session == nullptr || session->closed) {
    return true;
  }
  while (!session->child_authorities.empty()) {
    if (!CloseViteRecoveryChildAuthority(session->child_authorities.back())) {
      return false;
    }
  }
  if (session->directory_fd.Get() >= 0) {
    const int duplicate_fd = fcntl(session->directory_fd.Get(), F_DUPFD_CLOEXEC, 0);
    if (duplicate_fd < 0) {
      return false;
    }
    FileDescriptor retained_directory(duplicate_fd);
    FileDescriptor retained_lock;
    if (session->lock_fd.Get() >= 0) {
      const int duplicate_lock_fd = fcntl(session->lock_fd.Get(), F_DUPFD_CLOEXEC, 0);
      if (duplicate_lock_fd < 0) {
        return false;
      }
      retained_lock = FileDescriptor(duplicate_lock_fd);
      if (!CloseRecoveryFileDescriptor(&session->lock_fd)) {
        return false;
      }
    }
    if (!CloseRecoveryFileDescriptor(&session->directory_fd)) {
      if (retained_lock.Get() >= 0) {
        session->lock_fd = std::move(retained_lock);
      }
      return false;
    }
    if (retained_lock.Get() >= 0 && !CloseRecoveryFileDescriptor(&retained_lock)) {
      session->directory_fd = std::move(retained_directory);
      session->lock_fd = std::move(retained_lock);
      session->lock_held = true;
      return false;
    }
    session->lock_held = false;
    session->lock_identity = Identity{};
    ZeroizeString(&session->lock_name);
    if (!CloseRecoveryFileDescriptor(&retained_directory)) {
      session->directory_fd = std::move(retained_directory);
      return false;
    }
  } else if (session->lock_fd.Get() >= 0) {
    if (!CloseRecoveryFileDescriptor(&session->lock_fd)) {
      return false;
    }
    session->lock_held = false;
    session->lock_identity = Identity{};
    ZeroizeString(&session->lock_name);
  }
  if (!CloseRecoveryFileDescriptor(&session->scene_glass_fd) ||
      !CloseRecoveryFileDescriptor(&session->project_fd) ||
      !CloseRecoveryFileDescriptor(&session->project_parent_fd)) {
    return false;
  }
  session->closed = true;
  ZeroizeString(&session->project_name);
  ZeroizeString(&session->canonical_project_root);
  session->canonical_project_ancestor_identities.clear();
  if (session->slot_charged) {
    ReleaseAuthoritySlot(&active_vite_recovery_directory_sessions);
    session->slot_charged = false;
  }
  return true;
}
std::string RecoveryRequiredMarkerName(const std::string& manifest_name) {
  return "." + manifest_name + ".required";
}

std::string RecoveryBackupName(const std::string& temporary_name) {
  return temporary_name + ".prior";
}
std::string RecoveryRequiredManifest(const std::string& manifest_name) {
  constexpr const char* kManifestSuffix = ".recovery.v1.json";
  const size_t suffix_length = std::strlen(kManifestSuffix);
  if (manifest_name.size() <= suffix_length) {
    return std::string();
  }
  const std::string install_id = manifest_name.substr(0U, manifest_name.size() - suffix_length);
  return "{\n"
         "  \"version\": 1,\n"
         "  \"kind\": \"managed-vite-cache-recovery\",\n"
         "  \"installId\": \"" +
         install_id +
         "\",\n"
         "  \"status\": \"recovery-required\",\n"
         "  \"reason\": \"teardown-failed\"\n"
         "}\n";
}

bool OpenRecoveryFile(ViteRecoveryDirectorySession* session, const std::string& name,
                      FileDescriptor* output, Identity* identity, bool* exists) {
  struct stat linked{};
  if (fstatat(session->directory_fd.Get(), name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno != ENOENT || !ValidateRecoveryDirectorySession(session)) {
      return false;
    }
    *exists = false;
    return true;
  }
  if (!IsSafeViteRecoveryFile(linked, session->owner_uid)) {
    return false;
  }
  FileDescriptor opened(OpenFinalAt(session->directory_fd.Get(), name));
  struct stat opened_stat{};
  if (opened.Get() < 0 || fstat(opened.Get(), &opened_stat) != 0 ||
      !ValidateRecoveryLinkedFile(session->directory_fd.Get(), name.c_str(), opened.Get(),
                                  session->owner_uid, RecoveryIdentityFromStat(opened_stat)) ||
      !SameIdentity(linked, RecoveryIdentityFromStat(opened_stat)) ||
      !ValidateRecoveryDirectorySession(session)) {
    return false;
  }
  *exists = true;
  *identity = RecoveryIdentityFromStat(opened_stat);
  *output = std::move(opened);
  return true;
}

bool MarkRecoveryRequired(ViteRecoveryDirectorySession* session,
                          const std::string& manifest_name) {
  const std::string marker_name = RecoveryRequiredMarkerName(manifest_name);
  FileDescriptor marker(openat(session->directory_fd.Get(), marker_name.c_str(),
                               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (marker.Get() < 0) {
    if (errno != EEXIST) {
      return false;
    }
    FileDescriptor existing;
    Identity identity{};
    bool exists = false;
    return OpenRecoveryFile(session, marker_name, &existing, &identity, &exists) && exists &&
           CloseRecoveryFileDescriptor(&existing);
  }
  static constexpr char kRequiredMarker[] = "recovery-required\n";
  struct stat marker_stat{};
  struct stat marker_after{};
  if (fchmod(marker.Get(), 0600) != 0 || fstat(marker.Get(), &marker_stat) != 0 ||
      !IsSafeViteRecoveryFile(marker_stat, session->owner_uid) || !HasSafeAcl(marker.Get()) ||
      !ValidateRecoveryLinkedFile(session->directory_fd.Get(), marker_name.c_str(), marker.Get(),
                                  session->owner_uid, RecoveryIdentityFromStat(marker_stat)) ||
      !WriteAll(marker.Get(), reinterpret_cast<const unsigned char*>(kRequiredMarker),
                sizeof(kRequiredMarker) - 1U) ||
      fsync(marker.Get()) != 0 || fstat(marker.Get(), &marker_after) != 0 ||
      !IsSafeViteRecoveryFile(marker_after, session->owner_uid) || !HasSafeAcl(marker.Get()) ||
      !SameIdentity(marker_after, RecoveryIdentityFromStat(marker_stat)) ||
      !ValidateRecoveryLinkedFile(session->directory_fd.Get(), marker_name.c_str(), marker.Get(),
                                  session->owner_uid, RecoveryIdentityFromStat(marker_stat)) ||
      !CloseRecoveryFileDescriptor(&marker) || fsync(session->directory_fd.Get()) != 0 ||
      !ValidateRecoveryDirectorySession(session)) {
    return false;
  }
  return true;
}

bool ClearRecoveryRequiredMarker(ViteRecoveryDirectorySession* session,
                                 const std::string& manifest_name) {
  const std::string marker_name = RecoveryRequiredMarkerName(manifest_name);
  FileDescriptor marker;
  Identity marker_identity{};
  bool exists = false;
  if (!OpenRecoveryFile(session, marker_name, &marker, &marker_identity, &exists)) {
    return false;
  }
  if (!exists) {
    return true;
  }
  if (!ValidateRecoveryLinkedFile(session->directory_fd.Get(), marker_name.c_str(), marker.Get(),
                                  session->owner_uid, marker_identity) ||
      unlinkat(session->directory_fd.Get(), marker_name.c_str(), 0) != 0 ||
      !CloseRecoveryFileDescriptor(&marker) || fsync(session->directory_fd.Get()) != 0 ||
      !ValidateRecoveryDirectorySession(session)) {
    return false;
  }
  return true;
}

bool RestorePreviousRecoveryManifest(ViteRecoveryDirectorySession* session,
                                     const std::string& manifest_name,
                                     const std::string& temporary_name,
                                     const std::string& backup_name,
                                     FileDescriptor* temporary,
                                     const Identity& temporary_identity, bool had_previous,
                                     FileDescriptor* previous,
                                     const Identity& previous_identity) {
  if (temporary == nullptr ||
      !ValidateRecoveryLinkedFile(session->directory_fd.Get(), manifest_name.c_str(),
                                  temporary->Get(), session->owner_uid, temporary_identity) ||
      !RenameViteSnapshotNoReplace(session->directory_fd.Get(), manifest_name.c_str(),
                                   session->directory_fd.Get(), temporary_name.c_str())) {
    return false;
  }
  if (had_previous &&
      (!ValidateRecoveryLinkedFile(session->directory_fd.Get(), backup_name.c_str(), previous->Get(),
                                   session->owner_uid, previous_identity) ||
       !RenameViteSnapshotNoReplace(session->directory_fd.Get(), backup_name.c_str(),
                                    session->directory_fd.Get(), manifest_name.c_str()) ||
       !ValidateRecoveryLinkedFile(session->directory_fd.Get(), manifest_name.c_str(), previous->Get(),
                                   session->owner_uid, previous_identity))) {
    return false;
  }
  if (!ValidateRecoveryLinkedFile(session->directory_fd.Get(), temporary_name.c_str(),
                                  temporary->Get(), session->owner_uid, temporary_identity) ||
      unlinkat(session->directory_fd.Get(), temporary_name.c_str(), 0) != 0 ||
      fsync(session->directory_fd.Get()) != 0 || !ValidateRecoveryDirectorySession(session)) {
    return false;
  }
  return true;
}
bool RemoveRecoveryLinkedFile(ViteRecoveryDirectorySession* session, const std::string& name, int fd,
                              const Identity& identity) {
  return ValidateRecoveryLinkedFile(session->directory_fd.Get(), name.c_str(), fd,
                                    session->owner_uid, identity) &&
         unlinkat(session->directory_fd.Get(), name.c_str(), 0) == 0 &&
         fsync(session->directory_fd.Get()) == 0 && ValidateRecoveryDirectorySession(session);
}
bool CompensateRecoveryTemporaryFailure(ViteRecoveryDirectorySession* session,
                                        const std::string& manifest_name,
                                        const std::string& temporary_name, int temporary_fd,
                                        const Identity& temporary_identity,
                                        bool identity_captured) {
  return identity_captured &&
                 RemoveRecoveryLinkedFile(session, temporary_name, temporary_fd, temporary_identity)
             ? true
             : MarkRecoveryRequired(session, manifest_name);
}

void FinalizeViteRecoveryDirectorySession(napi_env, void* data, void*) {
  auto* session = static_cast<ViteRecoveryDirectorySession*>(data);
  if (!CloseViteRecoveryDirectorySession(session)) {
    session->finalization_retained = true;
    finalizing_vite_recovery_directory_sessions.push_back(session);
    return;
  }
  delete session;
}

bool UnwrapViteRecoveryDirectorySession(napi_env env, napi_value value,
                                        ViteRecoveryDirectorySession** output) {
  bool tagged = false;
  if (!GetObject(env, value, &value) ||
      !IsNapiStatusOk(napi_check_object_type_tag(
          env, value, &kViteRecoveryDirectorySessionTypeTag, &tagged)) ||
      !tagged || !IsNapiStatusOk(napi_unwrap(env, value, reinterpret_cast<void**>(output))) ||
      *output == nullptr) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}

bool RequireViteRecoveryDirectorySession(napi_env env, napi_value value,
                                         ViteRecoveryDirectorySession** output) {
  if (!UnwrapViteRecoveryDirectorySession(env, value, output)) {
    return false;
  }
  if (!ValidateRecoveryDirectorySession(*output)) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}

bool ParseViteRecoveryDirectoryOptions(napi_env env, napi_callback_info info, std::string* project_root,
                                       Identity* expected_project_identity, std::string* state_root,
                                       Identity* expected_state_identity, uid_t* owner_uid) {
  napi_value options;
  napi_value project_root_value;
  napi_value project_identity_value;
  napi_value state_root_value;
  napi_value state_identity_value;
  uint32_t parsed_owner = 0U;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "projectRoot", &project_root_value) ||
      !GetRequiredProperty(env, options, "expectedProjectRootIdentity", &project_identity_value) ||
      !GetRequiredProperty(env, options, "stateRoot", &state_root_value) ||
      !GetRequiredProperty(env, options, "expectedStateRootIdentity", &state_identity_value) ||
      !ParseCanonicalAbsolutePath(env, project_root_value, project_root) ||
      !ParseIdentity(env, project_identity_value, expected_project_identity) ||
      !ParseCanonicalAbsolutePath(env, state_root_value, state_root) ||
      !ParseIdentity(env, state_identity_value, expected_state_identity) ||
      !GetRequiredUint32(env, options, "expectedOwnerUid", UINT32_MAX, &parsed_owner) ||
      parsed_owner != static_cast<uint32_t>(geteuid())) {
    ThrowRecoveryDenied(env);
    return false;
  }
  *owner_uid = static_cast<uid_t>(parsed_owner);
  return true;
}

bool ParseViteRecoveryLockOptions(napi_env env, napi_callback_info info, napi_value* session_value,
                                  std::string* lock_name) {
  napi_value options;
  napi_value lock_name_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", session_value) ||
      !GetRequiredProperty(env, options, "lockName", &lock_name_value) ||
      !GetString(env, lock_name_value, lock_name, kMaximumPathComponentBytes) ||
      !IsViteRecoveryName(*lock_name, ".recovery.v1.lock")) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}
bool ParseViteRecoveryChildAuthorityOptions(napi_env env, napi_callback_info info,
                                            napi_value* session_value, std::string* launch_id) {
  napi_value options;
  napi_value launch_id_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", session_value) ||
      !GetRequiredProperty(env, options, "launchId", &launch_id_value) ||
      !GetString(env, launch_id_value, launch_id, 36U) || !IsViteRecoveryLaunchId(*launch_id)) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}

bool ParseViteRecoveryChildAuthorityCloseOptions(napi_env env, napi_callback_info info,
                                                 uint32_t* fd) {
  napi_value options;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredUint32(env, options, "fd", 0x7fffffffU, fd)) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}
bool ParseManagedViteChildLaunchAuthorityOptions(napi_env env, napi_callback_info info,
                                                  uint32_t* fd, std::string* launch_id,
                                                  std::string* install_id,
                                                  Identity* expected_state_root_identity,
                                                  uid_t* owner_uid) {
  napi_value options;
  napi_value launch_id_value;
  napi_value install_id_value;
  napi_value state_root_identity_value;
  uint32_t parsed_owner = 0U;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredUint32(env, options, "fd", 0x7fffffffU, fd) ||
      !GetRequiredProperty(env, options, "launchId", &launch_id_value) ||
      !GetRequiredProperty(env, options, "installId", &install_id_value) ||
      !GetRequiredProperty(env, options, "expectedStateRootIdentity", &state_root_identity_value) ||
      !GetString(env, launch_id_value, launch_id, 36U) || !IsViteRecoveryLaunchId(*launch_id) ||
      !GetString(env, install_id_value, install_id, 128U) || !IsViteCacheInstallId(*install_id) ||
      !ParseIdentity(env, state_root_identity_value, expected_state_root_identity) ||
      !GetRequiredUint32(env, options, "expectedOwnerUid", UINT32_MAX, &parsed_owner) ||
      parsed_owner != static_cast<uint32_t>(geteuid())) {
    ThrowRecoveryDenied(env);
    return false;
  }
  *owner_uid = static_cast<uid_t>(parsed_owner);
  return true;
}

bool ParseManagedViteChildLaunchAuthorityReleaseOptions(napi_env env, napi_callback_info info,
                                                         napi_value* authority_value) {
  napi_value options;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "authority", authority_value)) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}

bool ParseViteRecoveryReadOptions(napi_env env, napi_callback_info info, napi_value* session_value,
                                  std::string* manifest_name) {
  napi_value options;
  napi_value manifest_name_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", session_value) ||
      !GetRequiredProperty(env, options, "manifestName", &manifest_name_value) ||
      !GetString(env, manifest_name_value, manifest_name, kMaximumPathComponentBytes) ||
      !IsViteRecoveryName(*manifest_name, ".recovery.v1.json")) {
    ThrowRecoveryDenied(env);
    return false;
  }
  return true;
}

bool ParseViteRecoveryReplaceOptions(napi_env env, napi_callback_info info, napi_value* session_value,
                                     std::string* manifest_name, std::string* temporary_name,
                                     const unsigned char** bytes, size_t* byte_count) {
  napi_value options;
  napi_value manifest_name_value;
  napi_value temporary_name_value;
  napi_value bytes_value;
  bool is_buffer = false;
  void* source = nullptr;
  size_t source_length = 0U;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", session_value) ||
      !GetRequiredProperty(env, options, "manifestName", &manifest_name_value) ||
      !GetRequiredProperty(env, options, "temporaryName", &temporary_name_value) ||
      !GetRequiredProperty(env, options, "bytes", &bytes_value) ||
      !GetString(env, manifest_name_value, manifest_name, kMaximumPathComponentBytes) ||
      !GetString(env, temporary_name_value, temporary_name, kMaximumPathComponentBytes) ||
      !IsViteRecoveryName(*manifest_name, ".recovery.v1.json") ||
      !IsViteRecoveryTemporaryName(*temporary_name) ||
      !IsNapiStatusOk(napi_is_buffer(env, bytes_value, &is_buffer)) || !is_buffer ||
      !IsNapiStatusOk(napi_get_buffer_info(env, bytes_value, &source, &source_length)) ||
      source_length == 0U || source_length > kMaximumViteRecoveryManifestBytes) {
    ThrowRecoveryDenied(env);
    return false;
  }
  *bytes = static_cast<const unsigned char*>(source);
  *byte_count = source_length;
  return true;
}

bool WriteRecoveryManifest(ViteRecoveryDirectorySession* session, const std::string& manifest_name,
                           const std::string& temporary_name, const unsigned char* bytes,
                           size_t byte_count) {
  if (!RequireViteRecoveryLock(session)) {
    return false;
  }

  FileDescriptor marker;
  Identity marker_identity{};
  bool marker_exists = false;
  if (!OpenRecoveryFile(session, RecoveryRequiredMarkerName(manifest_name), &marker, &marker_identity,
                        &marker_exists) ||
      (marker_exists && !CloseRecoveryFileDescriptor(&marker))) {
    return false;
  }

  FileDescriptor previous;
  Identity previous_identity{};
  bool had_previous = false;
  if (!OpenRecoveryFile(session, manifest_name, &previous, &previous_identity, &had_previous)) {
    return false;
  }

  const std::string backup_name = RecoveryBackupName(temporary_name);
  struct stat backup_stat{};
  if (fstatat(session->directory_fd.Get(), backup_name.c_str(), &backup_stat, AT_SYMLINK_NOFOLLOW) == 0 ||
      errno != ENOENT) {
    return false;
  }

  FileDescriptor temporary(openat(session->directory_fd.Get(), temporary_name.c_str(),
                                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (temporary.Get() < 0) {
    return false;
  }

  struct stat retained_temporary_stat{};
  const bool retained_temporary_identity_captured =
      fstat(temporary.Get(), &retained_temporary_stat) == 0;
  const Identity retained_temporary_identity =
      retained_temporary_identity_captured
          ? RecoveryIdentityFromStat(retained_temporary_stat)
          : Identity{};
  struct stat temporary_stat{};
  if (fchmod(temporary.Get(), 0600) != 0 || fstat(temporary.Get(), &temporary_stat) != 0 ||
      !IsSafeViteRecoveryFile(temporary_stat, session->owner_uid) || !HasSafeAcl(temporary.Get()) ||
      !ValidateRecoveryLinkedFile(session->directory_fd.Get(), temporary_name.c_str(), temporary.Get(),
                                  session->owner_uid, RecoveryIdentityFromStat(temporary_stat)) ||
      !WriteAll(temporary.Get(), bytes, byte_count) || fsync(temporary.Get()) != 0) {
    if (!CompensateRecoveryTemporaryFailure(
            session, manifest_name, temporary_name, temporary.Get(), retained_temporary_identity,
            retained_temporary_identity_captured)) {
      return false;
    }
    return false;
  }
  const Identity temporary_identity = RecoveryIdentityFromStat(temporary_stat);
  struct stat temporary_after{};
  if (fstat(temporary.Get(), &temporary_after) != 0 ||
      !IsSafeViteRecoveryFile(temporary_after, session->owner_uid) || !HasSafeAcl(temporary.Get()) ||
      !SameIdentity(temporary_after, temporary_identity) ||
      !ValidateRecoveryLinkedFile(session->directory_fd.Get(), temporary_name.c_str(), temporary.Get(),
                                  session->owner_uid, temporary_identity) ||
      !ValidateRecoveryDirectorySession(session)) {
    (void)CompensateRecoveryTemporaryFailure(session, manifest_name, temporary_name, temporary.Get(),
                                             temporary_identity, true);
    return false;
  }

  if (had_previous &&
      (!RenameViteSnapshotNoReplace(session->directory_fd.Get(), manifest_name.c_str(),
                                   session->directory_fd.Get(), backup_name.c_str()) ||
       !ValidateRecoveryLinkedFile(session->directory_fd.Get(), backup_name.c_str(), previous.Get(),
                                   session->owner_uid, previous_identity) ||
       fsync(session->directory_fd.Get()) != 0)) {
    const bool restored =
        ValidateRecoveryLinkedFile(session->directory_fd.Get(), backup_name.c_str(), previous.Get(),
                                   session->owner_uid, previous_identity) &&
        RenameViteSnapshotNoReplace(session->directory_fd.Get(), backup_name.c_str(),
                                    session->directory_fd.Get(), manifest_name.c_str()) &&
        ValidateRecoveryLinkedFile(session->directory_fd.Get(), manifest_name.c_str(), previous.Get(),
                                   session->owner_uid, previous_identity) &&
        fsync(session->directory_fd.Get()) == 0 && ValidateRecoveryDirectorySession(session);
    if (!restored) {
      (void)MarkRecoveryRequired(session, manifest_name);
    }
    (void)CompensateRecoveryTemporaryFailure(session, manifest_name, temporary_name, temporary.Get(),
                                             temporary_identity, true);
    return false;
  }

  if (!RenameViteSnapshotNoReplace(session->directory_fd.Get(), temporary_name.c_str(),
                                   session->directory_fd.Get(), manifest_name.c_str())) {
    const bool restored =
        !had_previous ||
        (ValidateRecoveryLinkedFile(session->directory_fd.Get(), backup_name.c_str(), previous.Get(),
                                    session->owner_uid, previous_identity) &&
         RenameViteSnapshotNoReplace(session->directory_fd.Get(), backup_name.c_str(),
                                     session->directory_fd.Get(), manifest_name.c_str()) &&
         ValidateRecoveryLinkedFile(session->directory_fd.Get(), manifest_name.c_str(), previous.Get(),
                                    session->owner_uid, previous_identity) &&
         fsync(session->directory_fd.Get()) == 0 && ValidateRecoveryDirectorySession(session));
    if (!restored) {
      (void)MarkRecoveryRequired(session, manifest_name);
    }
    (void)CompensateRecoveryTemporaryFailure(session, manifest_name, temporary_name, temporary.Get(),
                                             temporary_identity, true);
    return false;
  }

  bool succeeded =
      ValidateRecoveryLinkedFile(session->directory_fd.Get(), manifest_name.c_str(), temporary.Get(),
                                 session->owner_uid, temporary_identity) &&
      fsync(session->directory_fd.Get()) == 0 && ValidateRecoveryDirectorySession(session);
  if (succeeded && had_previous) {
    succeeded = ValidateRecoveryLinkedFile(session->directory_fd.Get(), backup_name.c_str(), previous.Get(),
                                           session->owner_uid, previous_identity) &&
                unlinkat(session->directory_fd.Get(), backup_name.c_str(), 0) == 0 &&
                fsync(session->directory_fd.Get()) == 0 && ValidateRecoveryDirectorySession(session);
  }
  if (succeeded) {
    succeeded = ClearRecoveryRequiredMarker(session, manifest_name);
  }
  if (succeeded) {
    succeeded = CloseRecoveryFileDescriptor(&temporary);
  }
  if (succeeded) {
    return true;
  }

  const bool restored =
      RestorePreviousRecoveryManifest(session, manifest_name, temporary_name, backup_name, &temporary,
                                      temporary_identity, had_previous, &previous, previous_identity);
  if (!restored) {
    (void)MarkRecoveryRequired(session, manifest_name);
  }
  return false;
}

napi_value OpenViteRecoveryDirectorySession(napi_env env, napi_callback_info info) {
  std::string project_root;
  Identity expected_project_identity{};
  std::string state_root;
  Identity expected_state_identity{};
  uid_t owner_uid = 0;
  if (!ParseViteRecoveryDirectoryOptions(env, info, &project_root, &expected_project_identity,
                                         &state_root, &expected_state_identity, &owner_uid)) {
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_vite_recovery_directory_sessions,
                               kMaximumViteRecoveryDirectorySessions)) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  FileDescriptor project_parent;
  FileDescriptor project;
  FileDescriptor scene_glass;
  FileDescriptor runtime;
  FileDescriptor directory;
  Identity project_parent_identity{};
  Identity scene_glass_identity{};
  Identity runtime_identity{};
  std::string project_name;
  std::vector<Identity> project_ancestor_identities;
  if (!OpenViteRecoveryDirectory(project_root, expected_project_identity, state_root,
                                 expected_state_identity, owner_uid, &project_parent, &project,
                                 &scene_glass, &runtime, &directory, &project_parent_identity,
                                 &scene_glass_identity, &runtime_identity, &project_name,
                                 &project_ancestor_identities)) {
    ReleaseAuthoritySlot(&active_vite_recovery_directory_sessions);
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  auto* session = new (std::nothrow) ViteRecoveryDirectorySession{
      .project_parent_fd = std::move(project_parent),
      .project_fd = std::move(project),
      .scene_glass_fd = std::move(scene_glass),
      .runtime_fd = std::move(runtime),
      .directory_fd = std::move(directory),
      .lock_fd = FileDescriptor(),
      .project_parent_identity = project_parent_identity,
      .project_identity = expected_project_identity,
      .scene_glass_identity = scene_glass_identity,
      .runtime_identity = runtime_identity,
      .directory_identity = expected_state_identity,
      .lock_identity = Identity{},
      .owner_uid = owner_uid,
      .project_name = std::move(project_name),
      .canonical_project_root = std::move(project_root),
      .canonical_project_ancestor_identities = std::move(project_ancestor_identities),
      .slot_charged = true,
  };
  if (session == nullptr) {
    ReleaseAuthoritySlot(&active_vite_recovery_directory_sessions);
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  napi_value value;
  if (!IsNapiStatusOk(napi_create_object(env, &value)) ||
      !IsNapiStatusOk(napi_type_tag_object(env, value, &kViteRecoveryDirectorySessionTypeTag)) ||
      !IsNapiStatusOk(napi_wrap(env, value, session, FinalizeViteRecoveryDirectorySession, nullptr,
                                nullptr))) {
    if (!CloseViteRecoveryDirectorySession(session)) {
      session->finalization_retained = true;
      finalizing_vite_recovery_directory_sessions.push_back(session);
    } else {
      delete session;
    }
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  return value;
}

napi_value TryLockViteRecoveryDirectorySession(napi_env env, napi_callback_info info) {
  napi_value session_value;
  std::string lock_name;
  if (!ParseViteRecoveryLockOptions(env, info, &session_value, &lock_name)) {
    return nullptr;
  }
  ViteRecoveryDirectorySession* session = nullptr;
  if (!RequireViteRecoveryDirectorySession(env, session_value, &session)) {
    return nullptr;
  }
  if (session->lock_fd.Get() >= 0) {
    if (session->lock_name != lock_name) {
      ThrowRecoveryDenied(env);
      return nullptr;
    }
    napi_value result;
    if (!IsNapiStatusOk(napi_get_boolean(env, true, &result))) {
      ThrowRecoveryFailure(env);
      return nullptr;
    }
    return result;
  }

  FileDescriptor lock(openat(session->directory_fd.Get(), lock_name.c_str(),
                             O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
  struct stat lock_stat{};
  if (lock.Get() < 0 || fstat(lock.Get(), &lock_stat) != 0 ||
      !IsSafeViteRecoveryFile(lock_stat, session->owner_uid) || !HasSafeAcl(lock.Get()) ||
      !ValidateRecoveryLinkedFile(session->directory_fd.Get(), lock_name.c_str(), lock.Get(),
                                  session->owner_uid, RecoveryIdentityFromStat(lock_stat))) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  if (flock(lock.Get(), LOCK_EX | LOCK_NB) != 0) {
    const int error = errno;
    if (!CloseRecoveryFileDescriptor(&lock)) {
      ThrowRecoveryFailure(env);
      return nullptr;
    }
    if (error == EAGAIN || error == EWOULDBLOCK) {
      napi_value result;
      if (!IsNapiStatusOk(napi_get_boolean(env, false, &result))) {
        ThrowRecoveryFailure(env);
        return nullptr;
      }
      return result;
    }
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  session->lock_identity = RecoveryIdentityFromStat(lock_stat);
  session->lock_name = lock_name;
  session->lock_held = true;
  session->lock_fd = std::move(lock);
  if (!ValidateRecoveryDirectorySession(session)) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  napi_value result;
  if (!IsNapiStatusOk(napi_get_boolean(env, true, &result))) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  return result;
}
napi_value CreateViteRecoveryChildAuthority(napi_env env, napi_callback_info info) {
  napi_value session_value;
  std::string launch_id;
  if (!ParseViteRecoveryChildAuthorityOptions(env, info, &session_value, &launch_id)) {
    return nullptr;
  }
  ViteRecoveryDirectorySession* session = nullptr;
  if (!RequireViteRecoveryDirectorySession(env, session_value, &session) ||
      !RequireViteRecoveryLock(session)) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  std::string install_id;
  if (!session->child_authorities.empty() ||
      !RecoveryInstallIdFromLockName(session->lock_name, &install_id)) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  if (!TryAcquireAuthoritySlot(&active_vite_recovery_child_authorities_count,
                               kMaximumViteRecoveryChildAuthorities)) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }

  FileDescriptor child(OpenViteCacheDirectoryDescriptor(session->directory_fd.Get()));
  struct stat child_stat{};
  if (child.Get() < 0 || fstat(child.Get(), &child_stat) != 0 ||
      !IsSafeViteRecoveryDirectory(child_stat, session->owner_uid) || !HasSafeAcl(child.Get()) ||
      !SameIdentity(child_stat, session->directory_identity)) {
    ReleaseAuthoritySlot(&active_vite_recovery_child_authorities_count);
    ThrowRecoveryDenied(env);
    return nullptr;
  }

  napi_value result;
  napi_value fd;
  napi_value native_launch_id;
  if (!IsNapiStatusOk(napi_create_object(env, &result)) ||
      !IsNapiStatusOk(napi_create_int32(env, child.Get(), &fd)) ||
      !IsNapiStatusOk(
          napi_create_string_utf8(env, launch_id.c_str(), NAPI_AUTO_LENGTH, &native_launch_id)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "fd", fd)) ||
      !IsNapiStatusOk(napi_set_named_property(env, result, "launchId", native_launch_id))) {
    ReleaseAuthoritySlot(&active_vite_recovery_child_authorities_count);
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  if (flock(child.Get(), LOCK_EX | LOCK_NB) != 0 ||
      !SetManagedViteChildLaunchBinding(child.Get(), install_id, launch_id) ||
      fsync(child.Get()) != 0 ||
      !MatchesManagedViteChildLaunchBinding(child.Get(), getpid(), install_id, launch_id) ||
      !ValidateRecoveryDirectorySession(session)) {
    const bool needs_recovery =
        MatchesManagedViteChildLaunchBinding(child.Get(), getpid(), install_id, launch_id) &&
        (!ClearManagedViteChildLaunchBinding(child.Get(), install_id, launch_id) ||
         fsync(child.Get()) != 0);
    if (needs_recovery) {
      (void)MarkRecoveryRequired(session, install_id + ".recovery.v1.json");
    }
    ReleaseAuthoritySlot(&active_vite_recovery_child_authorities_count);
    ThrowRecoveryDenied(env);
    return nullptr;
  }

  const int issued_child_fd = child.Get();
  auto* authority = new (std::nothrow) ViteRecoveryChildAuthority{
      .fd = std::move(child),
      .issued_fd = issued_child_fd,
      .session = session,
      .identity = session->directory_identity,
      .install_id = install_id,
      .launch_id = launch_id,
      .slot_charged = true,
  };
  if (authority == nullptr) {
    const bool cleared = ClearManagedViteChildLaunchBinding(issued_child_fd, install_id, launch_id) &&
                         fsync(issued_child_fd) == 0;
    if (!cleared) {
      (void)MarkRecoveryRequired(session, install_id + ".recovery.v1.json");
    }
    ReleaseAuthoritySlot(&active_vite_recovery_child_authorities_count);
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  session->child_authorities.push_back(authority);
  active_vite_recovery_child_authorities.push_back(authority);
  return result;
}

napi_value CloseViteRecoveryChildAuthorityBinding(napi_env env, napi_callback_info info) {
  uint32_t parsed_fd = 0U;
  if (!ParseViteRecoveryChildAuthorityCloseOptions(env, info, &parsed_fd)) {
    return nullptr;
  }
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  const auto position =
      std::find_if(active_vite_recovery_child_authorities.begin(),
                   active_vite_recovery_child_authorities.end(), [parsed_fd](const auto* authority) {
                     return authority != nullptr &&
                            authority->issued_fd == static_cast<int>(parsed_fd);
                   });
  if (position == active_vite_recovery_child_authorities.end() ||
      !CloseViteRecoveryChildAuthority(*position)) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  return result;
}
napi_value VerifyManagedViteChildLaunchAuthority(napi_env env, napi_callback_info info) {
  uint32_t parsed_fd = 0U;
  std::string launch_id;
  std::string install_id;
  Identity expected_state_root_identity{};
  uid_t owner_uid = 0;
  if (!ParseManagedViteChildLaunchAuthorityOptions(
          env, info, &parsed_fd, &launch_id, &install_id, &expected_state_root_identity, &owner_uid)) {
    return nullptr;
  }
  if (active_managed_vite_child_launch_authority != nullptr ||
      !ValidateManagedViteChildLaunchAuthority(static_cast<int>(parsed_fd),
                                               expected_state_root_identity, owner_uid, install_id,
                                               launch_id)) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }

  auto* authority = new (std::nothrow) ManagedViteChildLaunchAuthority{
      .fd = FileDescriptor(static_cast<int>(parsed_fd)),
      .state_root_identity = expected_state_root_identity,
      .owner_uid = owner_uid,
      .install_id = install_id,
      .launch_id = launch_id,
  };
  if (authority == nullptr) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  napi_value authority_value;
  if (!IsNapiStatusOk(napi_create_object(env, &authority_value)) ||
      !IsNapiStatusOk(
          napi_type_tag_object(env, authority_value, &kManagedViteChildLaunchAuthorityTypeTag)) ||
      !IsNapiStatusOk(napi_wrap(env, authority_value, authority,
                                 FinalizeManagedViteChildLaunchAuthority, nullptr, nullptr))) {
    delete authority;
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  active_managed_vite_child_launch_authority = authority;
  return authority_value;
}

napi_value ReleaseManagedViteChildLaunchAuthority(napi_env env, napi_callback_info info) {
  napi_value authority_value;
  if (!ParseManagedViteChildLaunchAuthorityReleaseOptions(env, info, &authority_value)) {
    return nullptr;
  }
  ManagedViteChildLaunchAuthority* authority = nullptr;
  if (!UnwrapManagedViteChildLaunchAuthority(env, authority_value, &authority)) {
    return nullptr;
  }
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  if (!authority->released && !CloseManagedViteChildLaunchAuthority(authority)) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  return result;
}

napi_value ReadViteRecoveryManifest(napi_env env, napi_callback_info info) {
  napi_value session_value;
  std::string manifest_name;
  if (!ParseViteRecoveryReadOptions(env, info, &session_value, &manifest_name)) {
    return nullptr;
  }
  ViteRecoveryDirectorySession* session = nullptr;
  if (!RequireViteRecoveryDirectorySession(env, session_value, &session) ||
      !RequireViteRecoveryLock(session)) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  FileDescriptor marker;
  Identity marker_identity{};
  bool marker_exists = false;
  if (!OpenRecoveryFile(session, RecoveryRequiredMarkerName(manifest_name), &marker, &marker_identity,
                        &marker_exists) ||
      (marker_exists && !CloseRecoveryFileDescriptor(&marker))) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  if (marker_exists) {
    const std::string required = RecoveryRequiredManifest(manifest_name);
    napi_value result;
    void* copied = nullptr;
    if (required.empty() || required.size() > kMaximumViteRecoveryManifestBytes ||
        !IsNapiStatusOk(
            napi_create_buffer_copy(env, required.size(), required.data(), &copied, &result))) {
      ThrowRecoveryFailure(env);
      return nullptr;
    }
    return result;
  }
  struct stat linked{};
  if (fstatat(session->directory_fd.Get(), manifest_name.c_str(), &linked, AT_SYMLINK_NOFOLLOW) != 0) {
    if (errno == ENOENT && ValidateRecoveryDirectorySession(session)) {
      napi_value result;
      if (!IsNapiStatusOk(napi_get_null(env, &result))) {
        ThrowRecoveryFailure(env);
        return nullptr;
      }
      return result;
    }
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  FileDescriptor manifest(OpenFinalAt(session->directory_fd.Get(), manifest_name));
  struct stat before{};
  if (manifest.Get() < 0 || fstat(manifest.Get(), &before) != 0 ||
      !IsSafeViteRecoveryFile(linked, session->owner_uid) ||
      !IsSafeViteRecoveryFile(before, session->owner_uid) || !HasSafeAcl(manifest.Get()) ||
      !SameIdentity(linked, RecoveryIdentityFromStat(before)) || before.st_size <= 0) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }

  std::array<unsigned char, kMaximumViteRecoveryManifestBytes + 1U> bytes{};
  size_t offset = 0U;
  bool read_complete = false;
  while (offset <= kMaximumViteRecoveryManifestBytes) {
    const ssize_t count = pread(manifest.Get(), bytes.data() + offset, bytes.size() - offset,
                                static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      break;
    }
    if (count == 0) {
      read_complete = offset > 0U;
      break;
    }
    offset += static_cast<size_t>(count);
    if (offset > kMaximumViteRecoveryManifestBytes) {
      break;
    }
  }

  struct stat after{};
  const bool valid = read_complete && fstat(manifest.Get(), &after) == 0 &&
                     SameFileState(before, after) &&
                     ValidateRecoveryLinkedFile(session->directory_fd.Get(), manifest_name.c_str(),
                                                 manifest.Get(), session->owner_uid,
                                                 RecoveryIdentityFromStat(before)) &&
                     ValidateRecoveryDirectorySession(session);
  if (!valid || !CloseRecoveryFileDescriptor(&manifest)) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  napi_value result;
  void* copied = nullptr;
  if (!IsNapiStatusOk(napi_create_buffer_copy(env, offset, bytes.data(), &copied, &result))) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  return result;
}

napi_value ReplaceViteRecoveryManifest(napi_env env, napi_callback_info info) {
  napi_value session_value;
  std::string manifest_name;
  std::string temporary_name;
  const unsigned char* bytes = nullptr;
  size_t byte_count = 0U;
  if (!ParseViteRecoveryReplaceOptions(env, info, &session_value, &manifest_name, &temporary_name,
                                       &bytes, &byte_count)) {
    return nullptr;
  }
  ViteRecoveryDirectorySession* session = nullptr;
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  if (!RequireViteRecoveryDirectorySession(env, session_value, &session) ||
      !WriteRecoveryManifest(session, manifest_name, temporary_name, bytes, byte_count)) {
    ThrowRecoveryDenied(env);
    return nullptr;
  }
  return result;
}

napi_value CloseViteRecoveryDirectorySessionBinding(napi_env env, napi_callback_info info) {
  napi_value options;
  napi_value session_value;
  if (!GetSingleObjectArgument(env, info, &options) ||
      !GetRequiredProperty(env, options, "session", &session_value)) {
    return nullptr;
  }
  ViteRecoveryDirectorySession* session = nullptr;
  if (!UnwrapViteRecoveryDirectorySession(env, session_value, &session)) {
    return nullptr;
  }
  napi_value result;
  if (!IsNapiStatusOk(napi_get_undefined(env, &result))) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  if (!CloseViteRecoveryDirectorySession(session)) {
    ThrowRecoveryFailure(env);
    return nullptr;
  }
  return result;
}
napi_value Initialize(napi_env env, napi_value exports) {
  auto* snapshot_environment = new (std::nothrow) ViteSnapshotEnvironment{.env = env};
  if (snapshot_environment == nullptr) {
    return nullptr;
  }
  if (!IsNapiStatusOk(napi_set_instance_data(env, snapshot_environment,
                                             FinalizeViteSnapshotEnvironment, nullptr))) {
    delete snapshot_environment;
    return nullptr;
  }
  if (!IsNapiStatusOk(
          napi_add_env_cleanup_hook(env, CleanupViteSnapshotEnvironment, snapshot_environment))) {
    return nullptr;
  }
  const napi_property_descriptor properties[] = {
      {.utf8name = "secureReadBeneath",
       .method = SecureReadBeneath,
       .attributes = napi_default},
      {.utf8name = "acquireLifecycleLock",
       .method = AcquireLifecycleLock,
       .attributes = napi_default},
      {.utf8name = "releaseLifecycleLock",
       .method = ReleaseLifecycleLock,
       .attributes = napi_default},
      {.utf8name = "releaseLifecycleLockSession",
       .method = ReleaseLifecycleLockSession,
       .attributes = napi_default},
      {.utf8name = "revalidateLifecycleLock",
       .method = RevalidateLifecycleLock,
       .attributes = napi_default},
      {.utf8name = "validateExactCredential",
       .method = ValidateExactCredential,
       .attributes = napi_default},
      {.utf8name = "validateExactDirectory",
       .method = ValidateExactDirectory,
       .attributes = napi_default},
      {.utf8name = "readExactLifecycleWal",
       .method = ReadExactLifecycleWal,
       .attributes = napi_default},
      {.utf8name = "prepareLifecycleCreationIntent",
       .method = PrepareLifecycleCreationIntent,
       .attributes = napi_default},
      {.utf8name = "recoverLifecycleCreationIntent",
       .method = RecoverLifecycleCreationIntent,
       .attributes = napi_default},
      {.utf8name = "reserveCredentialFromIntent",
       .method = ReserveCredentialFromIntent,
       .attributes = napi_default},
      {.utf8name = "reserveLifecycleFileFromIntent",
       .method = ReserveCredentialFromIntent,
       .attributes = napi_default},
      {.utf8name = "reserveDirectoryFromIntent",
       .method = ReserveDirectoryFromIntent,
       .attributes = napi_default},
      {.utf8name = "retainReservationForRecovery",
       .method = RetainReservationForRecovery,
       .attributes = napi_default},
      {.utf8name = "createLifecycleStagedFile",
       .method = LifecycleCreationIntentRequired,
       .attributes = napi_default},
      {.utf8name = "reserveLifecycleStagedFile",
       .method = ReserveLifecycleStagedFile,
       .attributes = napi_default},
      {.utf8name = "writeLifecycleStagedFile",
       .method = WriteLifecycleStagedFile,
       .attributes = napi_default},
      {.utf8name = "validateLifecycleStagedFileReservation",
       .method = ValidateLifecycleStagedFileReservation,
       .attributes = napi_default},
      {.utf8name = "syncLifecycleStagedFileReservation",
       .method = SyncLifecycleStagedFileReservation,
       .attributes = napi_default},
      {.utf8name = "publishReservedLifecycleStagedFileNoReplace",
       .method = PublishReservedLifecycleStagedFileNoReplace,
       .attributes = napi_default},
      {.utf8name = "closeLifecycleStagedFileReservation",
       .method = CloseLifecycleStagedFileReservation,
       .attributes = napi_default},
      {.utf8name = "discardLifecycleStagedFileReservation",
       .method = DiscardLifecycleStagedFileReservation,
       .attributes = napi_default},
      {.utf8name = "publishLifecycleStagedFileNoReplace",
       .method = PublishLifecycleStagedFileNoReplace,
       .attributes = napi_default},
      {.utf8name = "replaceLifecycleStagedFileExact",
       .method = ReplaceLifecycleStagedFileExact,
       .attributes = napi_default},
      {.utf8name = "replaceReservedLifecycleFileExact",
       .method = ReplaceReservedLifecycleFileExact,
       .attributes = napi_default},
      {.utf8name = "replaceReservedLifecycleOrdinaryFileExact",
       .method = ReplaceReservedLifecycleOrdinaryFileExact,
       .attributes = napi_default},
      {.utf8name = "removeExactWal",
       .method = RemoveExactWal,
       .attributes = napi_default},
      {.utf8name = "removeExactCredential",
       .method = RemoveExactCredential,
       .attributes = napi_default},
      {.utf8name = "removeExactStagedFile",
       .method = RemoveExactStagedFile,
       .attributes = napi_default},
      {.utf8name = "quarantineLifecycleExactFile",
       .method = QuarantineLifecycleExactFile,
       .attributes = napi_default},
      {.utf8name = "quarantineLifecycleExactCredential",
       .method = QuarantineLifecycleExactCredential,
       .attributes = napi_default},
      {.utf8name = "finalizeLifecycleQuarantine",
       .method = FinalizeLifecycleQuarantineBinding,
       .attributes = napi_default},
      {.utf8name = "restoreLifecycleQuarantine",
       .method = RestoreLifecycleQuarantineBinding,
       .attributes = napi_default},
      {.utf8name = "createLifecycleStagedDirectory",
       .method = LifecycleCreationIntentRequired,
       .attributes = napi_default},
      {.utf8name = "publishLifecycleStagedDirectoryNoReplace",
       .method = PublishLifecycleStagedDirectoryNoReplace,
       .attributes = napi_default},
      {.utf8name = "publishReservedLifecycleStagedDirectoryNoReplace",
       .method = PublishReservedLifecycleStagedDirectoryNoReplace,
       .attributes = napi_default},
      {.utf8name = "closeLifecycleStagedDirectoryReservation",
       .method = CloseLifecycleStagedDirectoryReservation,
       .attributes = napi_default},
      {.utf8name = "syncLifecycleStagedDirectoryReservation",
       .method = SyncLifecycleStagedDirectoryReservation,
       .attributes = napi_default},
      {.utf8name = "discardLifecycleStagedDirectoryReservation",
       .method = DiscardLifecycleStagedDirectoryReservation,
       .attributes = napi_default},
      {.utf8name = "quarantineLifecycleExactDirectory",
       .method = QuarantineLifecycleExactDirectory,
       .attributes = napi_default},
      {.utf8name = "openViteCacheSession",
       .method = OpenViteCacheSession,
       .attributes = napi_default},
      {.utf8name = "scanViteCacheTree",
       .method = ScanViteCacheTree,
       .attributes = napi_default},
      {.utf8name = "scanViteCacheCanaries",
       .method = ScanViteCacheCanaries,
       .attributes = napi_default},
      {.utf8name = "watchViteCacheTree",
       .method = WatchViteCacheTree,
       .attributes = napi_default},
      {.utf8name = "closeViteCacheWatcher",
       .method = CloseViteCacheWatcherBinding,
       .attributes = napi_default},
      {.utf8name = "closeViteCacheSession",
       .method = CloseViteCacheSessionBinding,
       .attributes = napi_default},
      {.utf8name = "openViteRecoveryDirectorySession",
       .method = OpenViteRecoveryDirectorySession,
       .attributes = napi_default},
      {.utf8name = "tryLockViteRecoveryDirectorySession",
       .method = TryLockViteRecoveryDirectorySession,
       .attributes = napi_default},
      {.utf8name = "createViteRecoveryChildAuthority",
       .method = CreateViteRecoveryChildAuthority,
       .attributes = napi_default},
      {.utf8name = "closeViteRecoveryChildAuthority",
       .method = CloseViteRecoveryChildAuthorityBinding,
       .attributes = napi_default},
      {.utf8name = "verifyManagedViteChildLaunchAuthority",
       .method = VerifyManagedViteChildLaunchAuthority,
       .attributes = napi_default},
      {.utf8name = "releaseManagedViteChildLaunchAuthority",
       .method = ReleaseManagedViteChildLaunchAuthority,
       .attributes = napi_default},
      {.utf8name = "readViteRecoveryManifest",
       .method = ReadViteRecoveryManifest,
       .attributes = napi_default},
      {.utf8name = "replaceViteRecoveryManifest",
       .method = ReplaceViteRecoveryManifest,
       .attributes = napi_default},
      {.utf8name = "closeViteRecoveryDirectorySession",
       .method = CloseViteRecoveryDirectorySessionBinding,
       .attributes = napi_default},
      {.utf8name = "openViteSnapshotSession",
       .method = OpenViteSnapshotSession,
       .attributes = napi_default},
      {.utf8name = "createViteSnapshotStaging",
       .method = CreateViteSnapshotStaging,
       .attributes = napi_default},
      {.utf8name = "writeViteSnapshotStagingFile",
       .method = WriteViteSnapshotStagingFileBinding,
       .attributes = napi_default},
      {.utf8name = "publishViteSnapshotStaging",
       .method = PublishViteSnapshotStaging,
       .attributes = napi_default},
      {.utf8name = "persistViteSnapshotCommitment",
       .method = PersistViteSnapshotCommitment,
       .attributes = napi_default},
      {.utf8name = "discardViteSnapshotStaging",
       .method = DiscardViteSnapshotStaging,
       .attributes = napi_default},
      {.utf8name = "removeViteSnapshotPublished",
       .method = RemoveViteSnapshotPublished,
       .attributes = napi_default},
      {.utf8name = "closeViteSnapshotSession",
       .method = CloseViteSnapshotSessionBinding,
       .attributes = napi_default},
  };
  if (!IsNapiStatusOk(napi_define_properties(env, exports,
                                             sizeof(properties) / sizeof(properties[0]), properties))) {
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
