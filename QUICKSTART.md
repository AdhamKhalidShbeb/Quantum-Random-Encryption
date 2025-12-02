# QRE V3.0 - Quick Start Guide

**Get started in 60 seconds!**

---

## ⚡ Installation

### Step 1: Install Dependencies
```bash
chmod +x scripts/install_dependencies.sh
sudo ./scripts/install_dependencies.sh
```

### Step 2: Build
```bash
mkdir -p build && cd build
cmake ..
make
# Binary is now at: build/qre
```

### Step 3: Move Binary (Optional)
```bash
sudo cp qre /usr/local/bin/
```

---

## 🎯 Basic Usage

### Encrypt Any File
```bash
qre encrypt photo.jpg
# Creates: photo.qre
```

### Decrypt
```bash
qre decrypt photo.qre
# Restores: photo.jpg (original extension preserved!)
```

### Custom Output
```bash
qre encrypt video.mp4 secure.qre
qre decrypt secure.qre restored.mp4
```

---

## 🔒 Password Requirements

- Minimum 16 characters
- At least 2 uppercase letters
- At least 2 lowercase letters
- At least 2 digits
- At least 2 symbols
- Not in common password blacklist

**Example:** `MyUltraS3cur3P@ssw0rd!!`

---

## 📁 Supported File Types

**ALL file types supported:**
- Documents: PDF, DOCX, TXT, MD
- Images: JPG, PNG, GIF, SVG
- Videos: MP4, AVI, MKV
- Archives: ZIP, TAR, GZ
- And literally any other file!

---

## 🛠️ Troubleshooting

### Build fails?
```bash
# Make sure dependencies are installed
sudo ./scripts/install_dependencies.sh

# Try clean build
rm -rf build && mkdir build && cd build
cmake .. && make
```

### Permission denied?
```bash
chmod +x qre
# Or move to system path
sudo cp qre /usr/local/bin/
```

---

## 🚀 Advanced

### Verbose Output
```bash
qre encrypt file.zip --verbose
```

### Batch Encryption
```bash
for file in *.pdf; do
    qre encrypt "$file"
done
```

---

**Need help?** Check the full README.md
