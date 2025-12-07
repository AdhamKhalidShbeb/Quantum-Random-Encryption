#pragma once

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>

namespace QRE {

class TarManager {
public:
  // Check if tar command is available
  static bool is_tar_available() {
    return std::system("tar --version > /dev/null 2>&1") == 0;
  }

  // Create a tar archive from a directory
  // Returns true on success
  static bool create_archive(const std::string &source_dir,
                             const std::string &output_tar) {
    if (!is_tar_available()) {
      std::cerr << "Error: 'tar' command not found. Please install tar to use "
                   "batch operations."
                << std::endl;
      return false;
    }

    // Strip trailing slash if present
    std::string clean_source = source_dir;
    if (!clean_source.empty() && clean_source.back() == '/') {
      clean_source.pop_back();
    }

    // Construct command: tar -cf output.tar -C parent_dir directory_name
    // We use -C to change directory so the archive contains the relative path
    std::filesystem::path source_path(clean_source);
    std::string parent_dir = source_path.parent_path().string();
    std::string dir_name = source_path.filename().string();

    if (parent_dir.empty()) {
      parent_dir = ".";
    }

    std::stringstream cmd;
    cmd << "tar -cf \"" << output_tar << "\" -C \"" << parent_dir << "\" \""
        << dir_name << "\"";

    // Suppress output
    cmd << " > /dev/null 2>&1";

    int result = std::system(cmd.str().c_str());
    return result == 0;
  }

  // Extract a tar archive
  // Returns true on success
  static bool extract_archive(const std::string &input_tar,
                              const std::string &dest_dir = ".") {
    if (!is_tar_available()) {
      std::cerr << "Error: 'tar' command not found." << std::endl;
      return false;
    }

    // Create destination directory if it doesn't exist
    if (!dest_dir.empty() && dest_dir != ".") {
      std::filesystem::create_directories(dest_dir);
    }

    std::stringstream cmd;
    cmd << "tar -xf \"" << input_tar << "\"";

    if (!dest_dir.empty() && dest_dir != ".") {
      cmd << " -C \"" << dest_dir << "\"";
    }

    cmd << " > /dev/null 2>&1";

    int result = std::system(cmd.str().c_str());
    return result == 0;
  }
};

} // namespace QRE
