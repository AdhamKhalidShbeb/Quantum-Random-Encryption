# QRE V4.0 - Roadmap & Future Improvements

**Status:** Planning Phase  
**Target:** Q2 2025  
**Focus:** Performance, Features, Platform Expansion

---

## 🎯 Major Goals

### 1. **Multi-Platform Support** 🖥️
**Current:** Linux only  
**V4.0 Goal:** Windows + macOS support

**Tasks:**
- [ ] Abstract platform-specific code (file I/O, terminal handling)
- [ ] Replace `mlock`/`munlock` with cross-platform equivalents
- [ ] Windows: Use `VirtualLock`/`VirtualUnlock`
- [ ] macOS: Test on Apple Silicon (M1/M2)
- [ ] Create platform-specific installers (.msi, .dmg)

**Benefit:** 10x larger user base

---

### 2. **Hardware RNG Support** 🎲
**Current:** ANU QRNG (network) + /dev/urandom fallback  
**V4.0 Goal:** Support hardware RNGs

**Options:**
- [ ] Intel RDRAND/RDSEED instructions
- [ ] TPM 2.0 chip entropy
- [ ] USB hardware RNG devices (TrueRNG, Infinite Noise)
- [ ] Raspberry Pi hardware RNG

**Implementation:**
```cpp
enum EntropySource {
    QRNG_NETWORK,
    HARDWARE_RDRAND,
    HARDWARE_TPM,
    HARDWARE_USB,
    SYSTEM_URANDOM
};
// Auto-detect and use best available
```

**Benefit:** Faster, offline quantum-quality entropy

---

### 3. **Compression Support** 📦
**Current:** Encrypts raw data  
**V4.0 Goal:** Optional compression before encryption

**Features:**
- [ ] Integrate zlib or zstd
- [ ] Auto-detect if file benefits from compression
- [ ] Add flag: `--compress` or `-z`
- [ ] Store compression metadata in header

**Example:**
```bash
qre encrypt largefile.txt --compress
# Original: 100MB → Compressed+Encrypted: 25MB
```

**Benefit:** Smaller encrypted files for text/logs/code

---

### 4. **Batch Operations** 📁
**Current:** One file at a time  
**V4.0 Goal:** Encrypt multiple files/folders

**Features:**
- [ ] `qre encrypt folder/` - encrypts entire directory
- [ ] `qre encrypt *.pdf` - wildcard support
- [ ] Create `.tar.qre` archive of multiple files
- [ ] Progress bar for multi-file operations
- [ ] Parallel processing for speed

**Example:**
```bash
qre encrypt Documents/ --output backup.tar.qre
qre decrypt backup.tar.qre --extract-to restored/
```

**Benefit:** More practical for real-world use

---

### 5. **GUI Application** 🎨
**Current:** Command-line only  
**V4.0 Goal:** Optional graphical interface

**Options:**
- [ ] Qt framework (cross-platform)
- [ ] GTK (Linux-native)
- [ ] Electron (web-based, heavier)

**Features:**
- Drag & drop files
- Visual password strength meter
- Progress animation
- File browser integration (right-click → Encrypt)

**Benefit:** Accessible to non-technical users

---

### 6. **Key File Support** 🔑
**Current:** Password-only authentication  
**V4.0 Goal:** Optional key file + password (2FA)

**Implementation:**
```bash
qre encrypt doc.pdf --keyfile secret.key
# Requires BOTH password AND keyfile to decrypt
```

**Features:**
- [ ] Generate cryptographic key files
- [ ] Hash key file with SHA-512
- [ ] Combine password + keyfile in Argon2 KDF
- [ ] Store on USB drive for air-gapped security

**Benefit:** Protection even if password is compromised

---

### 7. **Cloud Integration** ☁️
**Current:** Local files only  
**V4.0 Goal:** Direct cloud storage encryption

**Features:**
- [ ] Encrypt-to-cloud: `qre upload file.pdf --to dropbox`
- [ ] Decrypt-from-cloud: `qre download backup.qre --from gdrive`
- [ ] Streaming encryption (don't store plaintext locally)
- [ ] Support: Dropbox, Google Drive, AWS S3, OneDrive

**Benefit:** Secure cloud backups without local copies

---

### 8. **Performance Optimizations** ⚡
**Current:** Single-threaded, pure software  
**V4.0 Goal:** Multi-core + hardware acceleration

**Improvements:**
- [ ] Multi-threaded encryption (split file into chunks)
- [ ] AVX2/AVX-512 SIMD instructions for XOR operations
- [ ] GPU acceleration (CUDA/OpenCL) for Argon2
- [ ] Memory-mapped I/O for large files

**Expected Gains:**
- Current: 80s for 1GB file
- Target: 20s for 1GB file (4x speedup)

---

### 9. **Advanced Crypto Features** 🔐

#### A. Public Key Encryption
**Current:** Symmetric (same password encrypts/decrypts)  
**V4.0 Option:** Asymmetric (public/private key pairs)

**Use case:**
```bash
# Alice encrypts for Bob using Bob's public key
qre encrypt message.txt --recipient bob.pub

# Only Bob can decrypt with his private key
qre decrypt message.qre --keyfile bob.key
```

#### B. Digital Signatures
**Feature:** Prove file was encrypted by you

```bash
qre encrypt doc.pdf --sign
# Creates doc.qre with embedded signature

qre verify doc.qre
# ✓ Signature valid, encrypted by: user@example.com
```

#### C. Time-Lock Encryption
**Feature:** File can only be decrypted after a certain date

```bash
qre encrypt will.pdf --unlock-after 2030-01-01
# Cannot be decrypted before Jan 1, 2030
```

---

### 10. **Testing & CI/CD** 🧪

**Current:** Manual testing  
**V4.0 Goal:** Automated testing pipeline

**Tasks:**
- [ ] Unit tests with Google Test framework
- [ ] Integration tests for encrypt/decrypt cycles
- [ ] Fuzzing with AFL++ for bug discovery
- [ ] GitHub Actions CI/CD
  - Auto-build on commit
  - Run tests on Ubuntu/Fedora/Arch
  - Static analysis (cppcheck, clang-tidy)
- [ ] Code coverage reports (>90% target)

---

### 11. **Better Error Messages** 💬
**Current:** Generic errors  
**V4.0 Goal:** Helpful, actionable messages

**Examples:**

**Before:**
```
Error: Invalid encrypted file format
```

**After:**
```
✗ Decryption failed: Invalid file format

Possible causes:
1. File is corrupted (failed integrity check)
2. Wrong password (HMAC verification failed)
3. File is not QRE-encrypted
4. Outdated QRE version (file format v3, you have v2)

Need help? Visit: https://github.com/user/QRE/issues
```

---

### 12. **Audit & Compliance** 📋

**Features:**
- [ ] Encryption audit log (who, when, what)
- [ ] Export logs for compliance (ISO 27001, HIPAA)
- [ ] Password policy enforcement (config file)
- [ ] Integration with enterprise key management (KMS)

---

## 📊 Priority Matrix

| Feature | Impact | Effort | Priority |
|---------|--------|--------|----------|
| Multi-Platform | High | High | P0 🔴 |
| Batch Operations | High | Medium | P0 🔴 |
| Hardware RNG | Medium | Medium | P1 🟡 |
| Compression | Medium | Low | P1 🟡 |
| GUI | High | High | P2 🟢 |
| Performance | Medium | High | P2 🟢 |
| Cloud Integration | Low | High | P3 🔵 |
| Public Key Crypto | Low | Very High | P3 🔵 |

---

## 🚀 Release Plan

### V4.0 Alpha (Q1 2025)
- ✅ Multi-platform support (Windows/Mac)
- ✅ Batch operations
- ✅ Hardware RNG detection

### V4.0 Beta (Q2 2025)
- ✅ Compression support
- ✅ Performance optimizations
- ✅ GUI prototype

### V4.0 Stable (Q3 2025)
- ✅ Full GUI
- ✅ Key file support
- ✅ Comprehensive testing

---

## 🤝 Community Contributions

**Want to help build V4.0?**

**Easy tasks (good first issues):**
- Better error messages
- Platform-specific installers
- Documentation improvements

**Medium tasks:**
- Compression integration
- Batch operation logic
- GUI mockups

**Advanced tasks:**
- Multi-platform abstraction
- Performance optimizations
- Public key crypto implementation

---

## 📝 Notes

**Philosophy for V4.0:**
- Security first (never sacrifice for convenience)
- Backward compatible (V4 can decrypt V3 files)
- Open standards (no vendor lock-in)
- User-friendly (grandma should be able to use it)

---

**Feedback?** Open an issue on GitHub!
