#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <sodium.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

#include "compression/CompressionManager.hpp"
#include "entropy/EntropyManager.hpp"
#include "password_blacklist.hpp"
#include "utils/TarManager.hpp"
#include <filesystem>

namespace fs = std::filesystem;

//
// SECURE MEMORY UTILITIES
//

// Securely wipe std::string (uses sodium_memzero with compiler barriers)
void secure_wipe_string(std::string &s) {
  if (!s.empty()) {
    sodium_memzero(&s[0], s.size());
    s.clear();
  }
}

// Securely wipe std::vector<unsigned char>
void secure_wipe_vector(std::vector<unsigned char> &v) {
  if (!v.empty()) {
    sodium_memzero(v.data(), v.size());
    v.clear();
  }
}

// Securely delete file by overwriting with random data before deletion
bool secure_delete_file(const std::string &filename) {
  // SECURITY: Open with O_NOFOLLOW to prevent TOCTOU symlink attacks
  // This atomically checks and opens the file
  int fd = open(filename.c_str(), O_RDWR | O_NOFOLLOW);
  if (fd < 0) {
    if (errno == ELOOP) {
      std::cerr << "SECURITY ERROR: " << filename
                << " is a symbolic link! Refusing to securely delete."
                << std::endl;
    }
    return false;
  }

  // Get file size
  struct stat file_stat;
  if (fstat(fd, &file_stat) != 0) {
    close(fd);
    return false;
  }
  size_t filesize = file_stat.st_size;

  if (filesize > 0) {
    // Overwrite with zeros (1MB buffer max)
    std::vector<unsigned char> zeros(std::min(filesize, size_t(1024 * 1024)),
                                     0);
    off_t written = 0;
    while (written < (off_t)filesize) {
      size_t to_write = std::min(zeros.size(), filesize - written);
      ssize_t result = write(fd, zeros.data(), to_write);
      if (result < 0) {
        close(fd);
        return false;
      }
      written += result;
    }
    fsync(fd); // Ensure data is written to disk
  }

  close(fd);

  // Now remove file
  return remove(filename.c_str()) == 0;
}

// Validate file path to prevent path traversal attacks
bool is_safe_path(const std::string &path) {
  // Reject paths with parent directory references (first line of defense)
  if (path.find("..") != std::string::npos) {
    return false;
  }

  // Reject absolute paths starting with /
  if (!path.empty() && path[0] == '/') {
    return false;
  }

  // SECURITY: Use canonical path resolution to detect symlink attacks
  // Note: This only works if the path exists, so we do basic checks first
  char resolved[PATH_MAX];
  char cwd[PATH_MAX];

  // Get current working directory
  if (getcwd(cwd, sizeof(cwd)) == nullptr) {
    // If we can't get CWD, be conservative and reject
    return false;
  }

  // Try to resolve the path (works for existing files)
  // For non-existent files (e.g., output files), check parent directory
  if (realpath(path.c_str(), resolved) != nullptr) {
    // Path exists - verify it's within current directory
    size_t cwd_len = strlen(cwd);
    if (strncmp(resolved, cwd, cwd_len) != 0) {
      return false; // Path escapes current directory
    }
  } else {
    // Path doesn't exist - check the parent directory
    std::string parent_path = path;
    size_t last_slash = parent_path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
      parent_path = parent_path.substr(0, last_slash);
      if (realpath(parent_path.c_str(), resolved) != nullptr) {
        size_t cwd_len = strlen(cwd);
        if (strncmp(resolved, cwd, cwd_len) != 0) {
          return false; // Parent escapes current directory
        }
      }
    }
    // If no parent or parent doesn't exist, rely on basic checks above
  }

  return true;
}

//
// SECURE PASSWORD CLASS
//

class SecurePassword {
private:
  char *data;
  size_t capacity;
  size_t length;

public:
  SecurePassword(size_t max_len = 256) {
    capacity = max_len;
    data = new char[capacity];
    memset(data, 0, capacity);

    // Lock memory to prevent paging to swap
    if (mlock(data, capacity) != 0) {
      std::cerr
          << "Warning: mlock failed for password (consider running with sudo)"
          << std::endl;
    }

    length = 0;
  }

  ~SecurePassword() {
    // Securely wipe password
    if (data) {
      sodium_memzero(data, capacity);
      munlock(data, capacity); // Only if data is valid
      delete[] data;
    }
  }

  // Prevent copying
  SecurePassword(const SecurePassword &) = delete;
  SecurePassword &operator=(const SecurePassword &) = delete;

  // Allow moving
  SecurePassword(SecurePassword &&other) noexcept
      : data(other.data), capacity(other.capacity), length(other.length) {
    other.data = nullptr;
    other.capacity = 0;
    other.length = 0;
  }

  void set(const char *input, size_t len) {
    if (len >= capacity) {
      len = capacity - 1;
    }
    length = len;
    memcpy(data, input, len);
    data[len] = '\0';
  }

  const char *c_str() const { return data; }
  size_t size() const { return length; }
  bool empty() const { return length == 0; }
};

//
// RAII CLEANUP GUARD
//

class SensitiveDataGuard {
private:
  std::vector<std::pair<void *, size_t>> tracked_buffers;

public:
  void track(void *ptr, size_t size) {
    if (ptr && size > 0) {
      tracked_buffers.push_back({ptr, size});
    }
  }

  ~SensitiveDataGuard() {
    // Automatically wipe all tracked buffers (even on exit() or exceptions)
    for (auto &buf : tracked_buffers) {
      if (buf.first && buf.second > 0) {
        // Only wipe, don't unlock (vectors handle their own memory)
        sodium_memzero(buf.first, buf.second);
        // munlock - but only if the memory is still valid
        // Skip munlock to avoid potential issues
      }
    }
    tracked_buffers.clear();
  }
};

//
// CONSTANTS
//

// Argon2id parameters (OWASP recommendations for high security)
const unsigned long long ARGON2_MEMORY = 64 * 1024 * 1024; // 64 MB
const unsigned long long ARGON2_OPS = 3;                   // 3 iterations

const int KEY_SIZE = 32; // 256 bits for AES-256
const int SALT_SIZE = 128;
const int NONCE_SIZE = 12; // 96-bit nonce for GCM

const int DELAY_SECONDS = 4;

const int MIN_PASSWORD_LENGTH = 16;
const int MIN_UPPERCASE = 2;
const int MIN_LOWERCASE = 2;
const int MIN_DIGITS = 2;
const int MIN_SYMBOLS = 2;

// Buffer size for reading files
const size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks

// File format version
const unsigned char FILE_FORMAT_VERSION = 0x03; // AES-256-GCM

// Global verbose flag (set via command line)
bool VERBOSE = false;

// Global compression level (set via command line)
QRE::CompressionLevel COMPRESSION_LEVEL = QRE::CompressionLevel::NONE;

// Compile-time safety checks
static_assert(KEY_SIZE == 32, "KEY_SIZE must be 32 bytes for AES-256");
static_assert(NONCE_SIZE == 12, "NONCE_SIZE must be 12 bytes for GCM");

//
// VERBOSE LOGGING
//

#define VLOG(msg)                                                              \
  if (VERBOSE) {                                                               \
    std::cout << "[DEBUG] " << msg << std::endl;                               \
  }

//
// FILE UTILITIES
//

std::string extract_extension(const std::string &filename) {
  size_t dot_pos = filename.find_last_of('.');
  if (dot_pos != std::string::npos && dot_pos < filename.length() - 1) {
    // Check for path separators after the dot (e.g. /path.to/file)
    size_t sep_pos = filename.find_last_of("/\\");
    if (sep_pos != std::string::npos && sep_pos > dot_pos) {
      return ""; // Dot was in directory name
    }

    std::string ext = filename.substr(dot_pos); // Returns ".jpg", ".txt", etc.

    // SECURITY: Sanitize extension to prevent path traversal
    // Reject extensions containing path separators or parent directory
    // references
    if (ext.find('/') != std::string::npos ||
        ext.find('\\') != std::string::npos ||
        ext.find("..") != std::string::npos) {
      return ""; // Invalid/malicious extension
    }

    return ext;
  }
  return ""; // No extension
}

//
// INPUT/OUTPUT UTILITIES
//

// RAII guard to ensure terminal echo is restored even on exceptions
class TerminalEchoGuard {
private:
  struct termios old_term;
  bool active;

public:
  TerminalEchoGuard() : active(false) {
    if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
      struct termios new_term = old_term;
      new_term.c_lflag &= ~ECHO;
      if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == 0) {
        active = true;
      }
    }
  }

  ~TerminalEchoGuard() {
    if (active) {
      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    }
  }

  // Prevent copying
  TerminalEchoGuard(const TerminalEchoGuard &) = delete;
  TerminalEchoGuard &operator=(const TerminalEchoGuard &) = delete;
};

std::string get_password_hidden() {
  TerminalEchoGuard guard; // RAII ensures restoration even on exception
  std::string password;

  std::getline(std::cin, password);
  std::cout << std::endl;

  if (std::cin.eof()) {
    return password;
  }

  return password;
}

void show_password_requirements() {
  std::cout << "\nPassword requirements:" << std::endl;
  std::cout << "  • Minimum length: " << MIN_PASSWORD_LENGTH << " characters"
            << std::endl;
  std::cout << "  • At least " << MIN_UPPERCASE << " uppercase letters"
            << std::endl;
  std::cout << "  • At least " << MIN_LOWERCASE << " lowercase letters"
            << std::endl;
  std::cout << "  • At least " << MIN_DIGITS << " digits" << std::endl;
  std::cout << "  • At least " << MIN_SYMBOLS << " symbols" << std::endl;
  std::cout << std::endl;
}

//
// CRYPTOGRAPHIC FUNCTIONS
//

std::vector<unsigned char> derive_key(const char *password, size_t password_len,
                                      const std::vector<unsigned char> &salt) {
  // SECURITY: Validate inputs
  if (password == nullptr || password_len == 0) {
    std::cerr << "CRITICAL ERROR: Invalid password for key derivation"
              << std::endl;
    exit(1);
  }
  if (salt.size() != SALT_SIZE) {
    std::cerr << "CRITICAL ERROR: Invalid salt size: " << salt.size()
              << std::endl;
    exit(1);
  }

  std::vector<unsigned char> key(KEY_SIZE);

  // Lock key in memory (track success for cleanup)
  bool key_locked = (mlock(key.data(), KEY_SIZE) == 0);
  if (!key_locked) {
    std::cerr << "Warning: mlock failed for key (consider running with sudo)"
              << std::endl;
  }

  VLOG("Deriving key with Argon2id (64 MB memory, 3 iterations)...");

  // Use Argon2id for secure key derivation
  if (crypto_pwhash(key.data(),    // Output key buffer
                    KEY_SIZE,      // Key length (128 bytes = 1024 bits)
                    password,      // Password
                    password_len,  // Password length
                    salt.data(),   // Salt (128 bytes from hardware RNG)
                    ARGON2_OPS,    // Operations/iterations (3)
                    ARGON2_MEMORY, // Memory usage (64 MB)
                    crypto_pwhash_ALG_ARGON2ID13 // Algorithm: Argon2id v1.3
                    ) != 0) {
    std::cerr << "Argon2id key derivation failed (out of memory)" << std::endl;
    sodium_memzero(key.data(), KEY_SIZE);
    if (key_locked) {
      munlock(key.data(), KEY_SIZE); // Only unlock if we locked it
    }
    exit(1);
  }

  return key;
}

//
// AES-256-GCM ENCRYPTION
//

// Encrypt data using AES-256-GCM (authenticated encryption)
std::vector<unsigned char>
encrypt_aes256gcm(const std::vector<unsigned char> &plaintext,
                  const std::vector<unsigned char> &key,
                  const std::vector<unsigned char> &nonce) {

  // SECURITY: Validate input sizes
  if (key.size() != 32) {
    std::cerr << "CRITICAL ERROR: Invalid key size for AES-256: " << key.size()
              << std::endl;
    exit(1);
  }
  if (nonce.size() != 12) {
    std::cerr << "CRITICAL ERROR: Invalid nonce size for GCM: " << nonce.size()
              << std::endl;
    exit(1);
  }

  // Check if AES-NI hardware support is available
  if (!crypto_aead_aes256gcm_is_available()) {
    std::cerr << "Error: AES-256-GCM not supported on this CPU" << std::endl;
    std::cerr << "       Requires Intel AES-NI or AMD equivalent" << std::endl;
    std::cerr << "       (Available on most CPUs since 2010)" << std::endl;
    exit(1);
  }

  // Allocate ciphertext buffer (plaintext + 16-byte authentication tag)
  std::vector<unsigned char> ciphertext(plaintext.size() +
                                        crypto_aead_aes256gcm_ABYTES);
  unsigned long long ciphertext_len;

  // Encrypt with built-in authentication
  crypto_aead_aes256gcm_encrypt(ciphertext.data(), // Output: ciphertext + tag
                                &ciphertext_len,   // Output length
                                plaintext.data(),  // Input plaintext
                                plaintext.size(),  // Input length
                                NULL, 0, // No additional authenticated data
                                NULL,    // No secret nonce
                                nonce.data(), // Public nonce (12 bytes)
                                key.data()    // 32-byte key
  );

  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

// Decrypt data using AES-256-GCM (with authentication verification)
std::vector<unsigned char>
decrypt_aes256gcm(const std::vector<unsigned char> &ciphertext,
                  const std::vector<unsigned char> &key,
                  const std::vector<unsigned char> &nonce) {

  // SECURITY: Validate input sizes
  if (key.size() != 32) {
    std::cerr << "CRITICAL ERROR: Invalid key size for AES-256: " << key.size()
              << std::endl;
    return {};
  }
  if (nonce.size() != 12) {
    std::cerr << "CRITICAL ERROR: Invalid nonce size for GCM: " << nonce.size()
              << std::endl;
    return {};
  }

  if (!crypto_aead_aes256gcm_is_available()) {
    std::cerr << "Error: AES-256-GCM not supported on this CPU" << std::endl;
    exit(1);
  }

  // Allocate plaintext buffer (ciphertext - 16-byte tag)
  if (ciphertext.size() < crypto_aead_aes256gcm_ABYTES) {
    std::cerr << "Error: Ciphertext too short for GCM tag" << std::endl;
    return {}; // Return empty on error
  }

  std::vector<unsigned char> plaintext(ciphertext.size() -
                                       crypto_aead_aes256gcm_ABYTES);
  unsigned long long plaintext_len;

  // Decrypt and verify authentication tag
  if (crypto_aead_aes256gcm_decrypt(
          plaintext.data(),  // Output plaintext
          &plaintext_len,    // Output length
          NULL,              // No secret nonce
          ciphertext.data(), // Input: ciphertext + tag
          ciphertext.size(), // Input length
          NULL, 0,           // No additional data
          nonce.data(),      // Public nonce
          key.data()         // 32-byte key
          ) != 0) {
    // Authentication failed (wrong key or tampered data)
    return {}; // Return empty vector on failure
  }

  plaintext.resize(plaintext_len);
  return plaintext;
}

//
// PASSWORD VALIDATION
//

bool validate_password(const std::string &password, std::string &error_msg) {
  // SECURITY: Check against blacklist of common weak passwords
  // (case-insensitive)
  std::string password_lower = password;
  for (auto &c : password_lower) {
    c = tolower(c);
  }

  if (PASSWORD_BLACKLIST.find(password_lower) != PASSWORD_BLACKLIST.end()) {
    error_msg = "This password is too common and easily guessable. Please "
                "choose a more unique password.";
    return false;
  }

  if (password.length() < MIN_PASSWORD_LENGTH) {
    error_msg = "Password must be at least " +
                std::to_string(MIN_PASSWORD_LENGTH) + " characters long";
    return false;
  }

  int uppercase = 0, lowercase = 0, digits = 0, symbols = 0;

  // SECURITY: Reject non-printable characters (prevents bypass attacks)
  for (char c : password) {
    if (!isprint(static_cast<unsigned char>(c)) && c != ' ') {
      error_msg = "Password contains invalid non-printable characters";
      return false;
    }

    if (isupper(c))
      uppercase++;
    else if (islower(c))
      lowercase++;
    else if (isdigit(c))
      digits++;
    else if (ispunct(c) || c == ' ')
      symbols++;
  }

  if (uppercase < MIN_UPPERCASE) {
    error_msg = "Password must contain at least " +
                std::to_string(MIN_UPPERCASE) + " uppercase letters";
    return false;
  }
  if (lowercase < MIN_LOWERCASE) {
    error_msg = "Password must contain at least " +
                std::to_string(MIN_LOWERCASE) + " lowercase letters";
    return false;
  }
  if (digits < MIN_DIGITS) {
    error_msg = "Password must contain at least " + std::to_string(MIN_DIGITS) +
                " digits";
    return false;
  }
  if (symbols < MIN_SYMBOLS) {
    error_msg = "Password must contain at least " +
                std::to_string(MIN_SYMBOLS) + " symbols";
    return false;
  }

  return true;
}

SecurePassword get_valid_password_for_encryption() {
  std::string temp_password; // Temporary std::string for input
  SecurePassword password;
  show_password_requirements();

  while (true) {
    std::cout << "Enter password: ";
    temp_password = get_password_hidden();

    if (temp_password.empty()) {
      if (std::cin.eof()) {
        std::cerr << "\n[ERROR] EOF reading password" << std::endl;
        exit(1);
      }
      std::cerr << "\n[ERROR] Password cannot be empty!" << std::endl;
      continue;
    }

    // 4-second delay for rate limiting (constant-time)
    sleep(DELAY_SECONDS);

    std::string error_msg;
    if (!validate_password(temp_password, error_msg)) {
      std::cerr << "\n[ERROR] " << error_msg << std::endl;
      std::cerr << "Please try again.\n" << std::endl;
      continue;
    }

    VLOG("Password meets all requirements!");

    // Transfer to SecurePassword and wipe temp
    password.set(temp_password.c_str(), temp_password.length());
    sodium_memzero(&temp_password[0], temp_password.size());
    temp_password.clear();

    return password;
  }
}

SecurePassword get_password_for_decryption() {
  std::cout << "Enter password: ";
  std::string temp_password = get_password_hidden();

  // SECURITY: Rate limiting to prevent brute force
  sleep(DELAY_SECONDS);

  // Transfer to SecurePassword and wipe temp
  SecurePassword password;
  password.set(temp_password.c_str(), temp_password.length());
  sodium_memzero(&temp_password[0], temp_password.size());
  temp_password.clear();

  if (password.empty()) {
    std::cerr << "Password cannot be empty!" << std::endl;
    exit(1);
  }

  return password;
}

//
//
// SELF-TEST ON STARTUP
//

bool self_test() {
  VLOG("Running self-test...");

  // Test 1: Argon2id KDF
  {
    std::vector<unsigned char> salt(SALT_SIZE, 0xAA);
    std::vector<unsigned char> key(KEY_SIZE);

    if (crypto_pwhash(key.data(), KEY_SIZE, "test", 4, salt.data(), ARGON2_OPS,
                      ARGON2_MEMORY, crypto_pwhash_ALG_ARGON2ID13) != 0) {
      std::cerr << "Self-test FAILED: Argon2id" << std::endl;
      return false;
    }
    VLOG("✓ Argon2id test passed");
  }

  // Test 2: AES-256-GCM encryption round-trip
  {
    // Skip if AES-NI not available
    if (!crypto_aead_aes256gcm_is_available()) {
      VLOG("⚠ Skipping AES-256-GCM test (no hardware support)");
    } else {
      std::vector<unsigned char> original = {0x48, 0x65, 0x6C, 0x6C,
                                             0x6F}; // "Hello"
      std::vector<unsigned char> key(KEY_SIZE, 0xCC);
      std::vector<unsigned char> nonce(NONCE_SIZE, 0xEE);

      // Encrypt
      std::vector<unsigned char> ciphertext =
          encrypt_aes256gcm(original, key, nonce);

      // Decrypt
      std::vector<unsigned char> decrypted =
          decrypt_aes256gcm(ciphertext, key, nonce);

      if (decrypted != original) {
        std::cerr << "Self-test FAILED: AES-256-GCM round-trip" << std::endl;
        return false;
      }
      VLOG("✓ AES-256-GCM encryption test passed");
    }
  }

  // Test 3: Compression round-trip
  {
    if (!QRE::compression_self_test(VERBOSE)) {
      std::cerr << "Self-test FAILED: Compression" << std::endl;
      return false;
    }
  }

  VLOG("All self-tests passed!");
  return true;
}

// FILE OPERATIONS
//

std::string auto_generate_output_filename(const std::string &input,
                                          const std::string &mode) {
  if (mode == "encrypt") {
    size_t dot_pos = input.find_last_of('.');
    if (dot_pos != std::string::npos) {
      return input.substr(0, dot_pos) + ".qre";
    }
    return input + ".qre";
  } else {
    // Decrypt mode: Recover original extension from header
    std::ifstream infile(input, std::ios::binary);
    if (infile) {
      // Skip version byte (1 byte)
      infile.seekg(1, std::ios::beg);
      if (infile) {
        unsigned char ext_len;
        infile.read((char *)&ext_len, 1);
        if (infile.gcount() == 1 && ext_len > 0) {
          std::vector<char> ext_buf(ext_len);
          infile.read(ext_buf.data(), ext_len);
          if (infile.gcount() == ext_len) {
            std::string stored_ext(ext_buf.begin(), ext_buf.end());

            // Remove .qre if present
            std::string base = input;
            if (base.length() > 4 && base.substr(base.length() - 4) == ".qre") {
              base = base.substr(0, base.length() - 4);
            }
            return base + stored_ext;
          }
        }
      }
    }

    // Fallback if no extension stored
    if (input.size() > 4 && input.substr(input.size() - 4) == ".qre") {
      return input.substr(0, input.size() - 4) + ".txt";
    }
    return input + "_decrypted.txt";
  }
}

// Helper: Get file size with overflow protection
size_t get_file_size(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary | std::ios::ate);
  if (!file)
    return 0;

  // SECURITY: Check for integer overflow on file size
  auto pos = file.tellg();
  if (pos < 0) {
    std::cerr << "Error reading file size" << std::endl;
    return 0;
  }

  // Check if file size exceeds SIZE_MAX (prevents overflow)
  if (static_cast<uintmax_t>(pos) > SIZE_MAX) {
    std::cerr << "File too large for this system" << std::endl;
    return 0;
  }

  return static_cast<size_t>(pos);
}

//
// ENCRYPTION/DECRYPTION OPERATIONS
//

void perform_encryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  // Check if input file exists before asking for password
  std::ifstream test_file(input_file);
  if (!test_file) {
    std::cerr << "Error: File not found: " << input_file << std::endl;
    exit(1);
  }
  test_file.close();

  // Get file size for progress bar
  size_t file_size = get_file_size(input_file);
  VLOG("File size: " << file_size << " bytes");

  // Open input file
  std::ifstream infile(input_file, std::ios::binary);
  if (!infile) {
    std::cerr << "Cannot open input file: " << input_file << std::endl;
    exit(1);
  }

  // Generate hardware random salt
  VLOG("Generating hardware random salt...");
  std::vector<unsigned char> salt =
      EntropyManager::get_instance().get_bytes(SALT_SIZE);
  if (salt.size() != SALT_SIZE) {
    std::cerr << "Failed to generate salt from hardware entropy source"
              << std::endl;
    exit(1);
  }
  if (mlock(salt.data(), SALT_SIZE) != 0) {
    std::cerr << "Warning: mlock failed for salt" << std::endl;
  }

  // Generate hardware random nonce
  VLOG("Generating hardware random nonce...");
  std::vector<unsigned char> nonce =
      EntropyManager::get_instance().get_bytes(NONCE_SIZE);
  if (nonce.size() != NONCE_SIZE) {
    std::cerr << "Failed to generate nonce from hardware entropy source"
              << std::endl;
    exit(1);
  }
  if (mlock(nonce.data(), NONCE_SIZE) != 0) {
    std::cerr << "Warning: mlock failed for nonce" << std::endl;
  }

  // Derive key
  VLOG("Deriving 256-bit AES encryption key...");
  std::vector<unsigned char> key =
      derive_key(password.c_str(), password.size(), salt);

  // Setup cleanup guard AFTER vectors are created to ensure it runs BEFORE
  // vectors are destroyed
  SensitiveDataGuard guard;
  guard.track(salt.data(), SALT_SIZE);
  guard.track(nonce.data(), NONCE_SIZE);
  guard.track(key.data(), KEY_SIZE);

  // Extract extension
  std::string original_ext = extract_extension(input_file);
  if (original_ext.length() > 255) {
    original_ext = original_ext.substr(0, 255);
  }
  unsigned char ext_len = (unsigned char)original_ext.length();

  // Check for empty file
  if (file_size == 0) {
    std::cerr << "Warning: Input file is empty (0 bytes)" << std::endl;
    std::cerr << "         Encryption will proceed, but output will only "
                 "contain metadata."
              << std::endl;
  }

  // Read entire file into memory
  VLOG("Reading file into memory...");
  std::vector<unsigned char> plaintext;

  try {
    plaintext.reserve(file_size);
  } catch (const std::bad_alloc &e) {
    std::cerr << "Error: Not enough memory to encrypt file ("
              << (file_size / (1024.0 * 1024.0)) << " MB)" << std::endl;
    std::cerr << "       Try closing other applications or use a system with "
                 "more RAM."
              << std::endl;
    exit(1);
  }

  try {
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    while (infile) {
      infile.read((char *)buffer.data(), CHUNK_SIZE);
      size_t bytes_read = infile.gcount();
      if (bytes_read == 0)
        break;
      plaintext.insert(plaintext.end(), buffer.begin(),
                       buffer.begin() + bytes_read);
    }
  } catch (const std::bad_alloc &e) {
    std::cerr << "Error: Out of memory while reading file" << std::endl;
    exit(1);
  }
  infile.close();

  // Compress plaintext if compression enabled
  std::vector<unsigned char> data_to_encrypt;
  if (COMPRESSION_LEVEL != QRE::CompressionLevel::NONE) {
    VLOG("Compressing with " << QRE::compression_level_name(COMPRESSION_LEVEL)
                             << "...");
    data_to_encrypt = QRE::compress_data(plaintext, COMPRESSION_LEVEL, VERBOSE);

    if (data_to_encrypt.empty()) {
      std::cerr << "Error: Compression failed" << std::endl;
      secure_wipe_vector(plaintext);
      exit(1);
    }

    // Securely wipe uncompressed plaintext
    secure_wipe_vector(plaintext);
  } else {
    // No compression - use plaintext directly
    data_to_encrypt = std::move(plaintext);
  }

  // Encrypt with AES-256-GCM
  // SECURITY: Atomically create output file with O_EXCL | O_NOFOLLOW
  // This prevents TOCTOU race - rejects if file exists or is symlink
  int out_fd =
      open(output_file.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (out_fd < 0) {
    if (errno == EEXIST) {
      std::cerr << "Error: Output file already exists: " << output_file
                << std::endl;
    } else if (errno == ELOOP) {
      std::cerr << "SECURITY ERROR: Output file is a symbolic link!"
                << std::endl;
    } else {
      std::cerr << "Error: Cannot create output file: " << output_file
                << std::endl;
    }
    exit(1);
  }

  // Encrypt with AES-256-GCM
  VLOG("Encrypting with AES-256-GCM...");
  std::vector<unsigned char> ciphertext =
      encrypt_aes256gcm(data_to_encrypt, key, nonce);

  // Securely wipe data_to_encrypt
  secure_wipe_vector(data_to_encrypt);

  // Write file header
  VLOG("Writing file header...");
  unsigned char header[2] = {FILE_FORMAT_VERSION, ext_len};
  if (write(out_fd, header, 2) != 2) {
    std::cerr << "Error: Failed to write file header" << std::endl;
    close(out_fd);
    exit(1);
  }

  // Write extension metadata
  if (ext_len > 0) {
    if (write(out_fd, original_ext.c_str(), ext_len) != ext_len) {
      std::cerr << "Error: Failed to write extension metadata" << std::endl;
      close(out_fd);
      exit(1);
    }
  }

  // Write salt and nonce
  if (write(out_fd, salt.data(), salt.size()) != (ssize_t)salt.size()) {
    std::cerr << "Error: Failed to write salt" << std::endl;
    close(out_fd);
    exit(1);
  }
  if (write(out_fd, nonce.data(), nonce.size()) != (ssize_t)nonce.size()) {
    std::cerr << "Error: Failed to write nonce" << std::endl;
    close(out_fd);
    exit(1);
  }

  // Write ciphertext (includes 16-byte GCM tag)
  if (write(out_fd, ciphertext.data(), ciphertext.size()) !=
      (ssize_t)ciphertext.size()) {
    std::cerr << "Error: Failed to write ciphertext (disk full?)" << std::endl;
    close(out_fd);
    exit(1);
  }

  // Append compression flag (1 byte) at the end
  // This ensures backward compatibility (old files don't have this byte)
  unsigned char comp_flag = static_cast<unsigned char>(COMPRESSION_LEVEL);
  if (write(out_fd, &comp_flag, 1) != 1) {
    std::cerr << "Error: Failed to write compression flag" << std::endl;
    close(out_fd);
    exit(1);
  }

  // Ensure data is written to disk
  if (fsync(out_fd) != 0) {
    std::cerr << "Warning: Failed to sync file to disk" << std::endl;
  }

  close(out_fd);

  // SECURITY: Securely delete original file
  VLOG("Securely deleting original file...");
  if (!secure_delete_file(input_file)) {
    std::cerr << "Warning: Could not securely delete original file: "
              << input_file << std::endl;
  }

  std::cout << "✓ Encrypted: " << output_file << std::endl;
  VLOG("  - Encryption: AES-256-GCM (Hardware Accelerated)");
  VLOG("  - Key derivation: Argon2id (64MB memory, 3 iterations)");
  VLOG("  - Authentication: GCM built-in (tamper-proof)");
}

void perform_decryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  // Check if input file exists
  std::ifstream test_file(input_file);
  if (!test_file) {
    std::cerr << "Error: File not found: " << input_file << std::endl;
    exit(1);
  }
  test_file.close();

  // Open input file
  std::ifstream infile(input_file, std::ios::binary);
  if (!infile) {
    std::cerr << "Cannot open input file: " << input_file << std::endl;
    exit(1);
  }

  // Verify file format version
  unsigned char version;
  infile.read((char *)&version, 1);
  if (!infile || infile.gcount() != 1) {
    std::cerr << "Invalid encrypted file format" << std::endl;
    exit(1);
  }

  if (version != 0x03) {
    std::cerr << "Invalid file format version: " << (int)version << std::endl;
    std::cerr << "This file may be corrupted or not a valid QRE encrypted file."
              << std::endl;
    exit(1);
  }

  // Read original file extension from header
  std::string original_ext = "";
  unsigned char ext_len;
  infile.read((char *)&ext_len, 1);
  if (ext_len > 0) {
    std::vector<char> ext_buf(ext_len);
    infile.read(ext_buf.data(), ext_len);
    if (infile.gcount() != ext_len) {
      std::cerr << "Invalid encrypted file format (corrupt extension)"
                << std::endl;
      exit(1);
    }
    original_ext.assign(ext_buf.begin(), ext_buf.end());
  }

  // Read salt
  std::vector<unsigned char> salt(SALT_SIZE);
  infile.read((char *)salt.data(), SALT_SIZE);
  if (infile.gcount() != SALT_SIZE) {
    std::cerr << "Invalid encrypted file format" << std::endl;
    exit(1);
  }

  // Read nonce (12 bytes for AES-256-GCM)
  std::vector<unsigned char> nonce(NONCE_SIZE);
  infile.read((char *)nonce.data(), NONCE_SIZE);
  if (static_cast<size_t>(infile.gcount()) != NONCE_SIZE) {
    std::cerr << "Invalid encrypted file format" << std::endl;
    exit(1);
  }

  // Derive key
  VLOG("Deriving decryption key...");
  std::vector<unsigned char> key =
      derive_key(password.c_str(), password.size(), salt);

  // Setup cleanup guard AFTER vectors are created
  SensitiveDataGuard guard;
  guard.track(salt.data(), SALT_SIZE);
  guard.track(nonce.data(), NONCE_SIZE);
  guard.track(key.data(), KEY_SIZE);

  VLOG("Decrypting with AES-256-GCM...");

  // Read entire ciphertext (includes 16-byte GCM tag)
  size_t file_size = get_file_size(input_file);
  size_t header_size = 1 + 1 + original_ext.length() + SALT_SIZE + NONCE_SIZE;
  size_t ciphertext_size = file_size - header_size;

  std::vector<unsigned char> ciphertext(ciphertext_size);
  infile.read((char *)ciphertext.data(), ciphertext_size);
  if ((size_t)infile.gcount() != ciphertext_size) {
    std::cerr << "Invalid encrypted file format (incomplete ciphertext)"
              << std::endl;
    exit(1);
  }

  // Decrypt (also verifies authentication tag)
  // STRATEGY: Try to decrypt assuming new format (flag at end).
  // If that fails, try assuming old format (no flag).

  std::vector<unsigned char> plaintext;
  QRE::CompressionLevel compression_used = QRE::CompressionLevel::NONE;

  // Check if last byte could be a compression flag
  if (ciphertext_size > 0) {
    unsigned char potential_flag = ciphertext.back();
    if (potential_flag <= 0x04) {
      // Potential new format. Try decrypting without the last byte.
      std::vector<unsigned char> ciphertext_new(ciphertext.begin(),
                                                ciphertext.end() - 1);

      // Try decrypt
      plaintext = decrypt_aes256gcm(ciphertext_new, key, nonce);

      if (!plaintext.empty()) {
        // Success! It was a new format file.
        compression_used = static_cast<QRE::CompressionLevel>(potential_flag);
        if (compression_used != QRE::CompressionLevel::NONE) {
          VLOG("Detected compression: "
               << QRE::compression_level_name(compression_used));
        }
      }
    }
  }

  // If plaintext is still empty, try old format (treat whole file as
  // ciphertext)
  if (plaintext.empty()) {
    plaintext = decrypt_aes256gcm(ciphertext, key, nonce);
    if (!plaintext.empty()) {
      VLOG("Detected old V3 format (no compression)");
    }
  }

  if (plaintext.empty()) {
    std::cerr << "\n[ERROR] Decryption failed! Wrong password or file has "
                 "been tampered with."
              << std::endl;
    exit(1);
  }

  VLOG("✓ Authentication and decryption successful");

  // Decompress if compression was used
  std::vector<unsigned char> final_plaintext;
  if (compression_used != QRE::CompressionLevel::NONE) {
    VLOG("Decompressing data...");
    final_plaintext = QRE::decompress_data(plaintext, VERBOSE);

    if (final_plaintext.empty()) {
      std::cerr << "Error: Decompression failed" << std::endl;
      secure_wipe_vector(plaintext);
      exit(1);
    }

    // Securely wipe compressed plaintext
    secure_wipe_vector(plaintext);
  } else {
    // No decompression needed
    final_plaintext = std::move(plaintext);
  }

  // SECURITY: Atomically create output file with O_CREAT | O_EXCL |
  // O_NOFOLLOW
  int out_fd =
      open(output_file.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (out_fd < 0) {
    if (errno == EEXIST) {
      std::cerr << "Error: Output file already exists: " << output_file
                << std::endl;
    } else if (errno == ELOOP) {
      std::cerr << "SECURITY ERROR: Output file is a symbolic link!"
                << std::endl;
    } else {
      std::cerr << "Cannot create output file: " << output_file << std::endl;
    }
    exit(1);
  }

  // Write decrypted data
  if (write(out_fd, final_plaintext.data(), final_plaintext.size()) !=
      (ssize_t)final_plaintext.size()) {
    std::cerr << "Error: Failed to write decrypted data (disk full?)"
              << std::endl;
    close(out_fd);
    exit(1);
  }

  if (fsync(out_fd) != 0) {
    std::cerr << "Warning: Failed to sync file to disk" << std::endl;
  }

  close(out_fd);

  // Securely wipe final_plaintext
  secure_wipe_vector(final_plaintext);

  infile.close();

  // SECURITY: Securely delete encrypted file
  VLOG("Securely deleting encrypted file...");
  if (!secure_delete_file(input_file)) {
    std::cerr << "Warning: Could not securely delete encrypted file"
              << std::endl;
  }

  std::cout << "✓ Decrypted: " << output_file << std::endl;
  VLOG("  - Decryption: AES-256-GCM (Hardware Accelerated)");
}

//
// MAIN
//

int main(int argc, char *argv[]) {
  // Initialize libsodium
  if (sodium_init() < 0) {
    std::cerr << "ERROR: libsodium initialization failed" << std::endl;
    return 1;
  }

  // SECURITY: Verify at least one entropy source is available
  auto available_sources =
      EntropyManager::get_instance().get_available_sources();
  if (available_sources.empty()) {
    std::cerr << "CRITICAL ERROR: No entropy sources available!" << std::endl;
    std::cerr << "Cannot generate cryptographically secure random numbers."
              << std::endl;
    return 1;
  }

  // Parse flags
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--verbose" || arg == "-v") {
      VERBOSE = true;
    } else if (arg == "--compress-fast") {
      COMPRESSION_LEVEL = QRE::CompressionLevel::FAST;
    } else if (arg == "--compress") {
      COMPRESSION_LEVEL = QRE::CompressionLevel::BALANCED;
    } else if (arg == "--compress-max") {
      COMPRESSION_LEVEL = QRE::CompressionLevel::MAX;
    } else if (arg == "--compress-ultra") {
      COMPRESSION_LEVEL = QRE::CompressionLevel::ULTRA;
    }
  }

  // Run self-test
  if (!self_test()) {
    std::cerr << "Self-test failed! Cannot continue." << std::endl;
    return 1;
  }

  if (argc < 3) {
    std::cout << "Usage:\n";
    std::cout << "  Encrypt: " << argv[0]
              << " encrypt <input> [output] [options]\n";
    std::cout << "           " << argv[0]
              << " encrypt <file1> <file2> ... [options]\n";
    std::cout << "           " << argv[0]
              << " encrypt <directory/> [options]\n";
    std::cout << "  Decrypt: " << argv[0]
              << " decrypt <input.qre> [output] [options]\n";
    std::cout << "           " << argv[0]
              << " decrypt <file1.qre> <file2.qre> ... [options]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  --verbose, -v         Enable debug logging\n";
    std::cout << "  --compress-fast       Fast compression (zstd level 1)\n";
    std::cout << "  --compress            Balanced compression (zstd level 6, "
                 "recommended)\n";
    std::cout
        << "  --compress-max        Maximum compression (zstd level 15)\n";
    std::cout << "  --compress-ultra      Ultra compression (zstd level 22)\n";
    std::cout << "\nBatch Operations:\n";
    std::cout << "  - Multiple files can be processed at once.\n";
    std::cout << "  - Directories are automatically archived (tar) before "
                 "encryption.\n";
    std::cout << "  - If multiple inputs are provided, output filenames are "
                 "auto-generated.\n";

    return 1;
  }

  // Extract mode and filenames (skip flags)
  std::vector<std::string> positional_args;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg[0] != '-') { // Not a flag
      positional_args.push_back(arg);
    }
  }

  if (positional_args.size() < 2) {
    std::cerr << "Error: Missing required arguments (mode and input file)"
              << std::endl;
    return 1;
  }

  std::string mode = positional_args[0];
  if (mode != "encrypt" && mode != "decrypt") {
    std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'" << std::endl;
    return 1;
  }

  // Identify inputs and outputs
  struct Task {
    std::string input;
    std::string output;
    bool is_directory;
    std::string temp_tar_file; // If directory, this is the intermediate tar
  };
  std::vector<Task> tasks;

  // Logic to distinguish "input output" vs "input1 input2"
  bool explicit_output = false;
  if (positional_args.size() == 3) {
    // Check if second arg exists
    std::string arg2 = positional_args[2];
    if (fs::exists(arg2)) {
      // Both exist -> Treat as two inputs
      // UNLESS in decrypt mode and arg2 is a directory (output dir? not
      // supported yet) For now, if it exists, it's an input. Warning: If user
      // intended to overwrite arg2, this will treat it as input! But O_EXCL
      // prevents overwrite anyway, so this is safe.
      explicit_output = false;
    } else {
      // arg2 does not exist -> Treat as output for arg1
      explicit_output = true;
    }
  }

  if (explicit_output) {
    // Single file case with explicit output
    Task t;
    t.input = positional_args[1];
    t.output = positional_args[2];
    t.is_directory = fs::is_directory(t.input);
    tasks.push_back(t);
  } else {
    // Batch mode (multiple inputs, auto-generated outputs)
    for (size_t i = 1; i < positional_args.size(); ++i) {
      Task t;
      t.input = positional_args[i];
      t.is_directory = fs::is_directory(t.input);

      if (t.is_directory && mode == "decrypt") {
        std::cerr << "Error: Cannot decrypt a directory: " << t.input
                  << std::endl;
        continue;
      }

      if (t.is_directory) {
        // For directory, we'll tar it first
        // Output will be dir_name.qre (which contains the tar)
        // We need to strip trailing slash if present for the filename
        std::string clean_path = t.input;
        if (clean_path.back() == '/')
          clean_path.pop_back();

        t.output = clean_path + ".qre";
        t.temp_tar_file = clean_path + ".tar";
      } else {
        t.output = auto_generate_output_filename(t.input, mode);
      }
      tasks.push_back(t);
    }
  }

  if (tasks.empty()) {
    std::cerr << "No valid tasks found." << std::endl;
    return 1;
  }

  // Get password once
  SecurePassword password = (mode == "encrypt")
                                ? get_valid_password_for_encryption()
                                : get_password_for_decryption();

  // Process tasks
  int success_count = 0;
  int fail_count = 0;

  for (auto &task : tasks) {
    std::cout << "\nProcessing: " << task.input << "..." << std::endl;

    // Handle Directory Encryption
    if (task.is_directory && mode == "encrypt") {
      VLOG("Input is a directory. Creating tar archive...");
      if (!QRE::TarManager::create_archive(task.input, task.temp_tar_file)) {
        std::cerr << "Failed to create tar archive for " << task.input
                  << std::endl;
        fail_count++;
        continue;
      }

      // Now encrypt the tar file
      // We use the temp tar file as input for encryption
      // The output is task.output (e.g., dir.qre)
      try {
        perform_encryption(task.temp_tar_file, task.output, password);
        success_count++;

        // Securely delete the temp tar file
        secure_delete_file(task.temp_tar_file);
      } catch (...) {
        std::cerr << "Encryption failed for " << task.input << std::endl;
        secure_delete_file(task.temp_tar_file); // Cleanup
        fail_count++;
      }
    }
    // Handle Normal File Encryption/Decryption
    else {
      // SECURITY: Validate file paths
      if (!is_safe_path(task.input) || !is_safe_path(task.output)) {
        std::cerr << "Skipping unsafe path: " << task.input << std::endl;
        fail_count++;
        continue;
      }

      if (task.input == task.output) {
        std::cerr << "Skipping: Input and output are the same: " << task.input
                  << std::endl;
        fail_count++;
        continue;
      }

      try {
        if (mode == "encrypt") {
          perform_encryption(task.input, task.output, password);
        } else {
          perform_decryption(task.input, task.output, password);

          // Check if decrypted file is a tar (simple check by extension for
          // now) If we decrypted "dir.qre" -> "dir.tar" (if stored ext was
          // .tar) Or if original input was "dir.tar.qre" -> "dir.tar"
          if (task.output.size() > 4 &&
              task.output.substr(task.output.size() - 4) == ".tar") {
            std::cout << "Detected TAR archive: " << task.output << std::endl;
            std::cout << "Extracting..." << std::endl;

            // Extract to current directory (or maybe a folder with the name of
            // the tar?) Let's extract to current dir for now to match behavior
            // of "tar -xf"
            if (QRE::TarManager::extract_archive(task.output)) {
              std::cout << "✓ Extracted archive" << std::endl;

              // Cleanup: Delete the intermediate tar file
              VLOG("Deleting intermediate tar file...");
              if (secure_delete_file(task.output)) {
                std::cout << "✓ Removed intermediate file: " << task.output
                          << std::endl;
              } else {
                std::cerr << "Warning: Failed to delete intermediate file: "
                          << task.output << std::endl;
              }
            } else {
              std::cerr << "Warning: Failed to extract archive" << std::endl;
            }
          }
        }
        success_count++;
      } catch (...) {
        std::cerr << "Operation failed for " << task.input << std::endl;
        fail_count++;
      }
    }
  }

  std::cout << "\nSummary: " << success_count << " succeeded, " << fail_count
            << " failed." << std::endl;

  return (fail_count == 0) ? 0 : 1;
}
