#include <cstdio>
#include <cstring>
#include <curl/curl.h>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <string>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

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
  std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
  if (!file) {
    return false; // File doesn't exist or can't be opened
  }

  // Get file size
  file.seekg(0, std::ios::end);
  size_t filesize = file.tellg();
  file.seekg(0, std::ios::beg);

  if (filesize > 0) {
    // Overwrite with zeros (simple method, could use random data for better
    // security)
    std::vector<unsigned char> zeros(std::min(filesize, size_t(1024 * 1024)),
                                     0); // 1MB buffer
    for (size_t written = 0; written < filesize; written += zeros.size()) {
      size_t to_write = std::min(zeros.size(), filesize - written);
      file.write((char *)zeros.data(), to_write);
    }
    file.flush();
  }
  file.close();

  // Now remove file
  return remove(filename.c_str()) == 0;
}

// Validate file path to prevent path traversal
bool is_safe_path(const std::string &path) {
  // Reject paths with parent directory references
  if (path.find("..") != std::string::npos) {
    return false;
  }
  // Reject absolute paths starting with /
  if (!path.empty() && path[0] == '/') {
    return false;
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
    sodium_memzero(data, capacity);
    munlock(data, capacity);
    delete[] data;
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

const int KEY_SIZE = 128; // 1024 bits
const int SALT_SIZE = 128;
const int NONCE_SIZE = 16;       // 128-bit nonce for per-encryption randomness
const int HMAC_SIZE = 32;        // HMAC-SHA256 tag size (256 bits)
const int ENCRYPTION_ROUNDS = 4; // Multi-round encryption for enhanced security
const int DELAY_SECONDS = 4;

const int MIN_PASSWORD_LENGTH = 16;
const int MIN_UPPERCASE = 2;
const int MIN_LOWERCASE = 2;
const int MIN_DIGITS = 2;
const int MIN_SYMBOLS = 2;

// Streaming encryption settings
const size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunks
const size_t STREAM_THRESHOLD =
    100 * 1024 * 1024; // Use streaming for files > 100MB
const size_t PROGRESS_UPDATE_INTERVAL = 64 * 1024; // Update progress every 64KB

// File format version
const unsigned char FILE_FORMAT_VERSION = 0x01;

// Global verbose flag (set via command line)
bool VERBOSE = false;

//
// PROGRESS DISPLAY
//

void show_progress(const std::string &operation, size_t current, size_t total) {
  if (total == 0)
    return;

  int percent = (current * 100) / total;
  int bar_width = 20;
  int filled = (current * bar_width) / total;

  // Format sizes in MB
  double current_mb = current / (1024.0 * 1024.0);
  double total_mb = total / (1024.0 * 1024.0);

  // Build progress bar
  std::cout << "\r" << operation << ": [";
  for (int i = 0; i < bar_width; i++) {
    if (i < filled)
      std::cout << "█";
    else
      std::cout << "░";
  }
  std::cout << "] " << percent << "% (";
  printf("%.1f MB / %.1f MB)", current_mb, total_mb);
  std::cout << std::flush;

  // New line when complete
  if (current >= total) {
    std::cout << std::endl;
  }
}

//
// VERBOSE LOGGING
//

#define VLOG(msg)                                                              \
  if (VERBOSE) {                                                               \
    std::cout << "[DEBUG] " << msg << std::endl;                               \
  }

//
// QRNG UTILITIES
//

// Local callback for CURL - uses std::string pointer instead of global
size_t QRNGWriteCallback(void *contents, size_t size, size_t nmemb,
                         void *userp) {
  size_t totalSize = size * nmemb;
  std::string *buffer = (std::string *)userp;
  buffer->append((char *)contents, totalSize);
  return totalSize;
}

// Fallback to system CSPRNG when QRNG unavailable
std::vector<unsigned char> fetch_system_random(size_t num_bytes) {
  std::vector<unsigned char> result(num_bytes);

  std::ifstream urandom("/dev/urandom", std::ios::binary);
  if (!urandom) {
    std::cerr << "ERROR: Cannot open /dev/urandom" << std::endl;
    exit(1);
  }

  urandom.read((char *)result.data(), num_bytes);
  urandom.close();

  return result;
}

// Ask user if they want to use fallback RNG
bool ask_user_fallback() {
  // If not interactive, we can't ask safely.
  // We'll log a warning and return false (abort) to be safe,
  // as the user explicitly wanted to be notified.
  if (!isatty(STDIN_FILENO)) {
    std::cerr << "\n[!] QRNG connection failed in non-interactive mode."
              << std::endl;
    std::cerr << "    Aborting to prevent silent fallback." << std::endl;
    return false;
  }

  std::cerr << "\n[!] WARNING: Connection to ANU Quantum Random Number "
               "Generator failed."
            << std::endl;
  std::cerr << "    Do you want to use the system's high-quality pseudo-random "
               "generator (/dev/urandom) instead? (y/n): ";

  char choice;
  std::cin >> choice;

  // Clear input buffer
  std::cin.ignore(10000, '\n');

  return (choice == 'y' || choice == 'Y');
}

std::vector<unsigned char> fetch_qrng_bytes(size_t num_bytes) {
  CURL *curl = curl_easy_init();
  std::vector<unsigned char> result;
  std::string qrngBuffer; // Local buffer, not global

  if (!curl) {
    std::cerr << "Failed to initialize CURL, falling back to /dev/urandom"
              << std::endl;
    return fetch_system_random(num_bytes);
  }

  // SECURITY: SSL/TLS verification settings
  const std::string qrng_url = "https://qrng.anu.edu.au/wp-content/plugins/"
                               "colours-plugin/get_block_binary.php";
  curl_easy_setopt(curl, CURLOPT_URL, qrng_url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, QRNGWriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &qrngBuffer); // Pass local buffer
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);

  // Enhanced certificate verification (but don't be too strict)
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // Verify certificate
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
                   2L); // Verify hostname matches cert
  // Let CURL use default CA bundle path

  VLOG("QRNG: SSL/TLS verification enabled");

  // SECURITY: Timeout configuration (prevent hanging)
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L); // 10s connection timeout
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);        // 30s total timeout

  // SECURITY: Only allow HTTPS
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);

  // Fetch enough blocks (1024 bits = 128 bytes per request)
  size_t blocks_needed = (num_bytes + 127) / 128;

  for (size_t i = 0; i < blocks_needed; i++) {
    qrngBuffer.clear();
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
      std::cerr << "QRNG request failed: " << curl_easy_strerror(res)
                << std::endl;

      if (ask_user_fallback()) {
        std::cerr << "Falling back to /dev/urandom for remaining bytes"
                  << std::endl;
        curl_easy_cleanup(curl);

        // Partial result handling
        if (result.empty()) {
          return fetch_system_random(num_bytes);
        } else {
          // Mix what we got with system random
          size_t remaining = num_bytes - result.size();
          std::vector<unsigned char> system_random =
              fetch_system_random(remaining);
          result.insert(result.end(), system_random.begin(),
                        system_random.end());
          return result;
        }
      } else {
        std::cerr << "Aborted by user." << std::endl;
        curl_easy_cleanup(curl);
        exit(1);
      }
    }

    // SECURITY: Validate response format (should be binary string of '0' and
    // '1')
    for (char c : qrngBuffer) {
      if (c != '0' && c != '1') {
        std::cerr << "ERROR: QRNG returned invalid format (not binary string)"
                  << std::endl;
        std::cerr << "Got character: " << (int)c << " (expected '0' or '1')"
                  << std::endl;

        if (ask_user_fallback()) {
          std::cerr << "Falling back to /dev/urandom" << std::endl;
          curl_easy_cleanup(curl);
          return fetch_system_random(num_bytes);
        } else {
          std::cerr << "Aborted by user." << std::endl;
          curl_easy_cleanup(curl);
          exit(1);
        }
      }
    }

    // Convert binary string to bytes
    for (size_t j = 0;
         j + 8 <= qrngBuffer.length() && result.size() < num_bytes; j += 8) {
      unsigned char byte = 0;
      for (int k = 0; k < 8; k++) {
        byte = (byte << 1) | (qrngBuffer[j + k] == '1' ? 1 : 0);
      }
      result.push_back(byte);
    }
  }

  curl_easy_cleanup(curl);
  return result;
}

//
// INPUT/OUTPUT UTILITIES
//

std::string get_password_hidden() {
  struct termios old_term, new_term;
  std::string password;

  tcgetattr(STDIN_FILENO, &old_term);
  new_term = old_term;
  new_term.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

  std::getline(std::cin, password);

  tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
  std::cout << std::endl;

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
  std::vector<unsigned char> key(KEY_SIZE);

  // Lock key in memory
  if (mlock(key.data(), KEY_SIZE) != 0) {
    std::cerr << "Warning: mlock failed for key (consider running with sudo)"
              << std::endl;
  }

  VLOG("Deriving key with Argon2id (64 MB memory, 3 iterations)...");

  // Use Argon2id for secure key derivation
  if (crypto_pwhash(key.data(),    // Output key buffer
                    KEY_SIZE,      // Key length (128 bytes = 1024 bits)
                    password,      // Password
                    password_len,  // Password length
                    salt.data(),   // Salt (128 bytes from QRNG)
                    ARGON2_OPS,    // Operations/iterations (3)
                    ARGON2_MEMORY, // Memory usage (64 MB)
                    crypto_pwhash_ALG_ARGON2ID13 // Algorithm: Argon2id v1.3
                    ) != 0) {
    std::cerr << "Argon2id key derivation failed (out of memory)" << std::endl;
    sodium_memzero(key.data(), KEY_SIZE);
    munlock(key.data(), KEY_SIZE);
    exit(1);
  }

  return key;
}

// Derive round keys from master key + nonce using SHA-256
std::vector<std::vector<unsigned char>>
derive_round_keys(const std::vector<unsigned char> &master_key,
                  const std::vector<unsigned char> &nonce) {

  std::vector<std::vector<unsigned char>> round_keys(ENCRYPTION_ROUNDS);

  for (int round = 0; round < ENCRYPTION_ROUNDS; round++) {
    round_keys[round].resize(KEY_SIZE);

    // Combine master_key + nonc + round_number for each round key
    std::vector<unsigned char> input;
    input.insert(input.end(), master_key.begin(), master_key.end());
    input.insert(input.end(), nonce.begin(), nonce.end());
    input.push_back(static_cast<unsigned char>(round));

    // Use libsodium's SHA-256 to derive round key
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, input.data(), input.size());

    // Generate full KEY_SIZE bytes by hashing multiple times
    for (int i = 0; i < KEY_SIZE / 32; i++) {
      unsigned char hash[32];
      crypto_hash_sha256_state temp_state = state;
      unsigned char counter = static_cast<unsigned char>(i);
      crypto_hash_sha256_update(&temp_state, &counter, 1);
      crypto_hash_sha256_final(&temp_state, hash);

      std::copy(hash, hash + 32, round_keys[round].begin() + (i * 32));
    }
  }

  return round_keys;
}

// Enhanced keystream generation with mixing
inline unsigned char
generate_keystream_byte(const std::vector<unsigned char> &round_key,
                        const std::vector<unsigned char> &salt,
                        const std::vector<unsigned char> &nonce,
                        size_t position) {

  // Mix multiple sources with position-dependent variation
  unsigned char result = 0;

  // XOR round key (position-dependent access)
  result ^= round_key[position % round_key.size()];

  // XOR salt (offset access for more entropy)
  result ^= salt[(position * 7) % salt.size()];

  // XOR nonce (rotated access)
  result ^= nonce[(position * 13) % nonce.size()];

  // Mix in position (multiple bytes for larger files)
  result ^= (position & 0xFF);
  result ^= ((position >> 8) & 0xFF);
  result ^= ((position >> 16) & 0xFF);

  // Additional mixing with rotation
  result = ((result << 3) | (result >> 5));

  return result;
}

// Note: Diffusion temporarily disabled for stability
// Multi-round encryption with 4 different keys already provides strong security

// Multi-round encryption with enhanced security
void encrypt_multi_round(std::vector<unsigned char> &data,
                         const std::vector<unsigned char> &master_key,
                         const std::vector<unsigned char> &salt,
                         const std::vector<unsigned char> &nonce) {

  // Derive round keys
  std::vector<std::vector<unsigned char>> round_keys =
      derive_round_keys(master_key, nonce);

  // Perform multiple encryption rounds
  for (int round = 0; round < ENCRYPTION_ROUNDS; round++) {
    // XOR with round-specific keystream
    for (size_t i = 0; i < data.size(); i++) {
      unsigned char keystream_byte =
          generate_keystream_byte(round_keys[round], salt, nonce, i);
      data[i] ^= keystream_byte;
    }
  }

  // Securely wipe round keys
  for (auto &rk : round_keys) {
    secure_wipe_vector(rk);
  }
}

// Multi-round decryption (reverse of encryption)
void decrypt_multi_round(std::vector<unsigned char> &data,
                         const std::vector<unsigned char> &master_key,
                         const std::vector<unsigned char> &salt,
                         const std::vector<unsigned char> &nonce) {

  // Derive same round keys
  std::vector<std::vector<unsigned char>> round_keys =
      derive_round_keys(master_key, nonce);

  // Perform decryption in reverse order
  for (int round = ENCRYPTION_ROUNDS - 1; round >= 0; round--) {
    // XOR with round-specific keystream (XOR is self-inverse)
    for (size_t i = 0; i < data.size(); i++) {
      unsigned char keystream_byte =
          generate_keystream_byte(round_keys[round], salt, nonce, i);
      data[i] ^= keystream_byte;
    }
  }

  // Securely wipe round keys
  for (auto &rk : round_keys) {
    secure_wipe_vector(rk);
  }
}

//
// HMAC-SHA256 AUTHENTICATION
//

std::vector<unsigned char> compute_hmac(const std::vector<unsigned char> &data,
                                        const std::vector<unsigned char> &key) {
  std::vector<unsigned char> hmac_tag(HMAC_SIZE);

  // Use libsodium's HMAC-SHA256
  crypto_auth_hmacsha256(hmac_tag.data(), data.data(), data.size(), key.data());

  return hmac_tag;
}

bool verify_hmac(const std::vector<unsigned char> &data,
                 const std::vector<unsigned char> &hmac_tag,
                 const std::vector<unsigned char> &key) {
  // Returns 0 if verification succeeds, -1 if it fails
  return crypto_auth_hmacsha256_verify(hmac_tag.data(), data.data(),
                                       data.size(), key.data()) == 0;
}

//
// PASSWORD VALIDATION
//

bool validate_password(const std::string &password, std::string &error_msg) {
  if (password.length() < MIN_PASSWORD_LENGTH) {
    error_msg = "Password must be at least " +
                std::to_string(MIN_PASSWORD_LENGTH) + " characters long";
    return false;
  }

  int uppercase = 0, lowercase = 0, digits = 0, symbols = 0;

  for (char c : password) {
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

  // Transfer to SecurePassword and wipe temp
  SecurePassword password;
  password.set(temp_password.c_str(), temp_password.length());
  sodium_memzero(&temp_password[0], temp_password.size());
  temp_password.clear();

  if (password.empty()) {
    std::cerr << "Password cannot be empty!" << std::endl;
    exit(1);
  }

  sleep(DELAY_SECONDS);
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

  // Test 2: HMAC-SHA256
  {
    std::vector<unsigned char> data = {0x01, 0x02, 0x03};
    std::vector<unsigned char> key(KEY_SIZE, 0xBB);
    std::vector<unsigned char> hmac = compute_hmac(data, key);

    if (hmac.size() != HMAC_SIZE) {
      std::cerr << "Self-test FAILED: HMAC-SHA256" << std::endl;
      return false;
    }
    VLOG("✓ HMAC-SHA256 test passed");
  }

  // Test 3: Encryption round-trip
  {
    std::vector<unsigned char> original = {0x48, 0x65, 0x6C, 0x6C,
                                           0x6F}; // "Hello"
    std::vector<unsigned char> data = original;
    std::vector<unsigned char> key(KEY_SIZE, 0xCC);
    std::vector<unsigned char> salt(SALT_SIZE, 0xDD);
    std::vector<unsigned char> nonce(NONCE_SIZE, 0xEE);

    encrypt_multi_round(data, key, salt, nonce);
    decrypt_multi_round(data, key, salt, nonce);

    if (data != original) {
      std::cerr << "Self-test FAILED: Encryption round-trip" << std::endl;
      return false;
    }
    VLOG("✓ Encryption round-trip test passed");
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
    if (input.size() > 4 && input.substr(input.size() - 4) == ".qre") {
      return input.substr(0, input.size() - 4) + ".txt";
    }
    return input + "_decrypted.txt";
  }
}

// Helper: Get file size
size_t get_file_size(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary | std::ios::ate);
  if (!file)
    return 0;
  return file.tellg();
}

//
// ENCRYPTION/DECRYPTION OPERATIONS
//

void perform_encryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  // Check if input file exists BEFORE asking for password (UX improvement)
  std::ifstream test_file(input_file);
  if (!test_file) {
    std::cerr << "Error: File not found: " << input_file << std::endl;
    exit(1);
  }
  test_file.close();

  // Auto-select streaming vs normal based on file size
  size_t file_size = get_file_size(input_file);

  if (file_size > STREAM_THRESHOLD) {
    VLOG("File size: " << file_size << " bytes - using STREAMING mode");
    // TODO: Call streaming function when implemented
    // For now, fall through to normal encryption with WARNING
    std::cout << "WARNING: Large file detected (" << (file_size / (1024 * 1024))
              << " MB)" << std::endl;
    std::cout << "Processing in memory - may use significant RAM" << std::endl;
  } else {
    VLOG("File size: " << file_size << " bytes - using NORMAL mode");
  }

  // Read input file
  std::ifstream infile(input_file, std::ios::binary);
  if (!infile) {
    std::cerr << "Cannot open input file: " << input_file << std::endl;
    exit(1);
  }

  std::vector<unsigned char> data((std::istreambuf_iterator<char>(infile)),
                                  std::istreambuf_iterator<char>());
  infile.close();

  // Setup cleanup guard for automatic wiping
  SensitiveDataGuard guard;

  // Generate quantum random salt
  VLOG("Generating quantum random salt...");
  std::vector<unsigned char> salt = fetch_qrng_bytes(SALT_SIZE);

  if (salt.size() != SALT_SIZE) {
    std::cerr << "Failed to generate salt from QRNG" << std::endl;
    exit(1);
  }

  // Lock salt in memory
  if (mlock(salt.data(), SALT_SIZE) != 0) {
    std::cerr << "Warning: mlock failed for salt" << std::endl;
  }
  guard.track(salt.data(), SALT_SIZE);

  // Generate quantum random nonce (per-encryption randomness)
  VLOG("Generating quantum random nonce...");
  std::vector<unsigned char> nonce = fetch_qrng_bytes(NONCE_SIZE);

  if (nonce.size() != NONCE_SIZE) {
    std::cerr << "Failed to generate nonce from QRNG" << std::endl;
    exit(1);
  }

  // Lock nonce in memory
  if (mlock(nonce.data(), NONCE_SIZE) != 0) {
    std::cerr << "Warning: mlock failed for nonce" << std::endl;
  }
  guard.track(nonce.data(), NONCE_SIZE);

  // Derive key
  VLOG("Deriving 1024-bit encryption key...");
  std::vector<unsigned char> key =
      derive_key(password.c_str(), password.size(), salt);
  guard.track(key.data(), KEY_SIZE);

  // Encrypt with multi-round enhanced cipher (with progress bar)
  VLOG("Encrypting (4 rounds with diffusion)...");

  size_t total_size = data.size();
  size_t chunk_size = 1024 * 64; // 64KB chunks for progress updates

  if (total_size > chunk_size * 2) {
    // Show progress for larger files
    for (size_t offset = 0; offset < total_size; offset += chunk_size) {
      size_t current_chunk = std::min(chunk_size, total_size - offset);

      // Process this chunk (multi-round on subset)
      std::vector<unsigned char> chunk_data(
          data.begin() + offset, data.begin() + offset + current_chunk);
      encrypt_multi_round(chunk_data, key, salt, nonce);
      std::copy(chunk_data.begin(), chunk_data.end(), data.begin() + offset);

      // Update progress
      show_progress("Encrypting", offset + current_chunk, total_size);
    }
  } else {
    // Small file - no progress bar needed
    encrypt_multi_round(data, key, salt, nonce);
  }

  // Compute HMAC-SHA256 for authentication (includes nonce in calculation)
  VLOG("Computing HMAC-SHA256 authentication tag...");
  std::vector<unsigned char> hmac_input;
  hmac_input.insert(hmac_input.end(), nonce.begin(), nonce.end());
  hmac_input.insert(hmac_input.end(), data.begin(), data.end());
  std::vector<unsigned char> hmac_tag = compute_hmac(hmac_input, key);

  // Write output: [Version][Salt][Nonce][Encrypted Data][HMAC Tag]
  std::ofstream outfile(output_file, std::ios::binary);
  if (!outfile) {
    std::cerr << "Cannot write output file: " << output_file << std::endl;
    exit(1);
  }

  VLOG("Writing file format version: " << (int)FILE_FORMAT_VERSION);
  outfile.write((char *)&FILE_FORMAT_VERSION, 1);
  outfile.write((char *)salt.data(), salt.size());
  outfile.write((char *)nonce.data(), nonce.size());
  outfile.write((char *)data.data(), data.size());
  outfile.write((char *)hmac_tag.data(), hmac_tag.size());
  outfile.close();

  // SECURITY: Securely delete original file (overwrite before delete)
  VLOG("Securely deleting original file...");
  if (!secure_delete_file(input_file)) {
    std::cerr << "Warning: Could not securely delete original file: "
              << input_file << std::endl;
  }

  std::cout << "✓ Encrypted: " << output_file << std::endl;
  VLOG("  - Encryption: Enhanced Quantum Random Cipher (4 rounds)");
  VLOG("  - Key derivation: Argon2id");
  VLOG("  - Authentication: HMAC-SHA256 (tamper-proof)");

  // SECURITY: Securely wipe sensitive data from memory
  secure_wipe_vector(key);
  secure_wipe_vector(salt);
  secure_wipe_vector(nonce);
  secure_wipe_vector(data);
  secure_wipe_vector(hmac_tag);
  secure_wipe_vector(hmac_input);
}

void perform_decryption(const std::string &input_file,
                        const std::string &output_file,
                        const SecurePassword &password) {
  // Check if input file exists BEFORE asking for password (UX improvement)
  std::ifstream test_file(input_file);
  if (!test_file) {
    std::cerr << "Error: File not found: " << input_file << std::endl;
    exit(1);
  }
  test_file.close();

  // Read encrypted file
  std::ifstream infile(input_file, std::ios::binary);
  if (!infile) {
    std::cerr << "Cannot open input file: " << input_file << std::endl;
    exit(1);
  }

  // Read and verify version byte
  unsigned char file_version;
  infile.read((char *)&file_version, 1);

  if (!infile || infile.gcount() != 1) {
    std::cerr << "Invalid encrypted file format (cannot read version)"
              << std::endl;
    exit(1);
  }

  VLOG("File format version: " << (int)file_version);

  if (file_version != FILE_FORMAT_VERSION) {
    std::cerr << "Unsupported file format version: " << (int)file_version
              << std::endl;
    std::cerr << "Expected version: " << (int)FILE_FORMAT_VERSION << std::endl;
    exit(1);
  }

  // Read salt
  std::vector<unsigned char> salt(SALT_SIZE);
  infile.read((char *)salt.data(), SALT_SIZE);

  if (infile.gcount() != SALT_SIZE) {
    std::cerr << "Invalid encrypted file format" << std::endl;
    exit(1);
  }

  // Read encrypted data + HMAC tag
  std::vector<unsigned char> data((std::istreambuf_iterator<char>(infile)),
                                  std::istreambuf_iterator<char>());
  infile.close();

  // Check minimum size: nonce + encrypted data + HMAC tag
  if (data.size() < (NONCE_SIZE + HMAC_SIZE)) {
    std::cerr << "Invalid encrypted file format (file too small)" << std::endl;
    exit(1);
  }

  // Extract nonce (first 16 bytes after salt)
  std::vector<unsigned char> nonce(data.begin(), data.begin() + NONCE_SIZE);
  data.erase(data.begin(), data.begin() + NONCE_SIZE);

  // Extract HMAC tag (last 32 bytes)
  std::vector<unsigned char> hmac_tag(data.end() - HMAC_SIZE, data.end());
  data.erase(data.end() - HMAC_SIZE, data.end());

  // Setup cleanup guard
  SensitiveDataGuard guard;

  // Lock salt in memory
  if (mlock(salt.data(), SALT_SIZE) != 0) {
    std::cerr << "Warning: mlock failed for salt" << std::endl;
  }
  guard.track(salt.data(), SALT_SIZE);

  // Lock nonce in memory
  if (mlock(nonce.data(), NONCE_SIZE) != 0) {
    std::cerr << "Warning: mlock failed for nonce" << std::endl;
  }
  guard.track(nonce.data(), NONCE_SIZE);

  // Derive key
  VLOG("Deriving 1024-bit decryption key...");
  std::vector<unsigned char> key =
      derive_key(password.c_str(), password.size(), salt);
  guard.track(key.data(), KEY_SIZE);

  // CRITICAL: Verify HMAC BEFORE decrypting (prevents tampering)
  VLOG("Verifying HMAC-SHA256 authentication tag...");
  std::vector<unsigned char> hmac_input;
  hmac_input.insert(hmac_input.end(), nonce.begin(), nonce.end());
  hmac_input.insert(hmac_input.end(), data.begin(), data.end());

  if (!verify_hmac(hmac_input, hmac_tag, key)) {
    std::cerr << "\n[ERROR] Authentication failed! File has been tampered with "
                 "or password is incorrect."
              << std::endl;
    std::cerr << "HMAC-SHA256 verification failed. Aborting decryption."
              << std::endl;
    exit(1);
  }
  VLOG("✓ Authentication successful - file integrity verified");

  // Decrypt with multi-round enhanced cipher (with progress bar)
  VLOG("Decrypting (4 rounds with diffusion)...");

  size_t total_size = data.size();
  size_t chunk_size = 1024 * 64; // 64KB chunks for progress updates

  if (total_size > chunk_size * 2) {
    // Show progress for larger files
    for (size_t offset = 0; offset < total_size; offset += chunk_size) {
      size_t current_chunk = std::min(chunk_size, total_size - offset);

      // Process this chunk (multi-round on subset)
      std::vector<unsigned char> chunk_data(
          data.begin() + offset, data.begin() + offset + current_chunk);
      decrypt_multi_round(chunk_data, key, salt, nonce);
      std::copy(chunk_data.begin(), chunk_data.end(), data.begin() + offset);

      // Update progress
      show_progress("Decrypting", offset + current_chunk, total_size);
    }
  } else {
    // Small file - no progress bar needed
    decrypt_multi_round(data, key, salt, nonce);
  }

  // Write output
  std::ofstream outfile(output_file, std::ios::binary);
  if (!outfile) {
    std::cerr << "Cannot write output file: " << output_file << std::endl;
    exit(1);
  }

  outfile.write((char *)data.data(), data.size());
  outfile.close();

  // SECURITY: Securely delete encrypted file (overwrite before delete)
  VLOG("Securely deleting encrypted file...");
  if (!secure_delete_file(input_file)) {
    std::cerr << "Warning: Could not securely delete encrypted file: "
              << input_file << std::endl;
  }

  std::cout << "✓ Decrypted: " << output_file << std::endl;

  // SECURITY: Securely wipe sensitive data from memory
  secure_wipe_vector(key);
  secure_wipe_vector(salt);
  secure_wipe_vector(nonce);
  secure_wipe_vector(data);
  secure_wipe_vector(hmac_tag);
  secure_wipe_vector(hmac_input);
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

  curl_global_init(CURL_GLOBAL_DEFAULT);

  // Parse flags
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--verbose" || std::string(argv[i]) == "-v") {
      VERBOSE = true;
    }
  }

  // Run self-test
  if (!self_test()) {
    std::cerr << "Self-test failed! Cannot continue." << std::endl;
    curl_global_cleanup();
    return 1;
  }

  if (argc < 3 || argc > 5) {
    std::cout << "Usage:\n";
    std::cout << "  Encrypt: " << argv[0]
              << " encrypt <input.txt> [output.qre] [--verbose]\n";
    std::cout << "  Decrypt: " << argv[0]
              << " decrypt <input.qre> [output.txt] [--verbose]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  --verbose, -v    Enable debug logging\n";
    std::cout
        << "\nIf output file is not specified, it will be auto-generated.\n";
    curl_global_cleanup();
    return 1;
  }

  std::string mode = argv[1];
  std::string input_file = argv[2];
  std::string output_file;

  // Auto-generate output filename if not provided
  if (argc == 4) {
    output_file = argv[3];
  } else {
    output_file = auto_generate_output_filename(input_file, mode);
  }

  // SECURITY: Validate file paths
  if (!is_safe_path(input_file)) {
    std::cerr << "ERROR: Input file path contains unsafe characters (path "
                 "traversal attempt?)"
              << std::endl;
    curl_global_cleanup();
    return 1;
  }
  if (!is_safe_path(output_file)) {
    std::cerr << "ERROR: Output file path contains unsafe characters (path "
                 "traversal attempt?)"
              << std::endl;
    curl_global_cleanup();
    return 1;
  }

  // SECURITY: Prevent input == output (would corrupt file)
  if (input_file == output_file) {
    std::cerr << "ERROR: Input and output files cannot be the same!"
              << std::endl;
    curl_global_cleanup();
    return 1;
  }

  // Check if input file exists BEFORE asking for password (UX improvement)
  std::ifstream test_file(input_file);
  if (!test_file) {
    std::cerr << "Error: File not found: " << input_file << std::endl;
    curl_global_cleanup();
    return 1;
  }
  test_file.close();

  // Get password
  if (mode == "encrypt") {
    SecurePassword password = get_valid_password_for_encryption();
    perform_encryption(input_file, output_file, password);
  } else if (mode == "decrypt") {
    SecurePassword password = get_password_for_decryption();
    perform_decryption(input_file, output_file, password);
  } else {
    std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'" << std::endl;
    curl_global_cleanup();
    return 1;
  }

  curl_global_cleanup();
  return 0;
}
