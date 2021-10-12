## xalwart.crypto
[![c++](https://img.shields.io/badge/c%2B%2B-20-6c85cf)](https://isocpp.org/)
[![cmake](https://img.shields.io/badge/cmake-%3E=2.8.12-success)](https://cmake.org/)
[![alpine](https://img.shields.io/badge/Alpine_Linux-0D597F?style=flat&logo=alpine-linux&logoColor=white)](https://alpinelinux.org/)
[![ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat&logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![macOS](https://img.shields.io/badge/macOS-343D46?style=flat&logo=apple&logoColor=F0F0F0)](https://www.apple.com/macos)

### Build Status
| @ | Build |
|---|---|
| Dev branch: | [![CI](https://github.com/YuriyLisovskiy/xalwart.crypto/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/YuriyLisovskiy/xalwart.crypto/actions/workflows/ci.yml?query=branch%3Adev) |
| Master branch: | [![CI](https://github.com/YuriyLisovskiy/xalwart.crypto/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/YuriyLisovskiy/xalwart.crypto/actions/workflows/ci.yml?query=branch%3Amaster) |

## Requirements
The following compilers are tested with the CI system, and are known to work on:

Alpine Linux and Ubuntu:
* g++ 10 or later
* clang++ 10 or later

macOS:
* clang++ 12 or later

To build the library from source CMake 2.8.12 or later is required.

### Dependencies
The following libraries are required:
- [openssl@1.1/1.1.1l](https://github.com/openssl/openssl) or later:
  ```bash
  # Ubuntu
  sudo apt-get install libssl-dev
  
  # macOS
  brew install openssl
  ```
- [xalwart.base](https://github.com/YuriyLisovskiy/xalwart.base) 0.x.x or later

## Compile from Source
* `BUILD_SHARED_LIBS` means to build a shared or static library (`ON` by default).

Specific options for macOS:
* `XW_OPENSSL_DIR` sets version of OpenSSL library (`openssl@1.1/1.1.1l` by default).
```bash
git clone https://github.com/YuriyLisovskiy/xalwart.crypto.git
cd xalwart.crypto
mkdir build && cd build
cmake -D CMAKE_BUILD_TYPE=Release ..
make xalwart.crypto && make install
```

## Testing
```bash
mkdir build && cd build
cmake -D CMAKE_BUILD_TYPE=Debug \
      -D XW_CONFIGURE_TESTS=ON \
      ..
make unittests-all
valgrind --leak-check=full ./tests/unittests-all
```
