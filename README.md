# 🔐 Lightweight HMAC-SHA256 & SHA-256 Engine in Pure C

[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Standard](https://img.shields.io/badge/Compliance-RFC_2104-orange.svg)](https://tools.ietf.org/html/rfc2104)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[English](#english) | [中文说明](#中文说明)

---

## English

A lightweight, standalone, and completely dependency-free cryptographic library implementing the **SHA-256** hash algorithm and the **HMAC-SHA256** (Keyed-Hash Message Authentication Code) wrapper in pure standard C. 

This repository showcases a complete implementation from bitwise primitives up to application-level MAC tag generation, strictly compliant with **RFC 2104** and **FIPS PUB 180-4**.

### 🚀 Key Technical Highlights

* **Zero Dependencies**: Built entirely using native C types (`uint8`, `uint32`, `uint64`). No OpenSSL or external crypto runtimes required—ideal for embedded platforms, IoT MCUs, and bare-metal environments.
* **Stream-Ready Design (Chunk-by-Chunk)**: Implements the industry-standard `Init`, `Update`, and `Final` architectural pattern. It buffers fragmented input and flushes a 512-bit message block via `sha256_Transform` only when filled, allowing you to process unbounded data streams or massive files with a constant memory footprint.
* **Strict RFC 2104 Key Dimensioning**: 
  * Automatically zero-pads keys shorter than the 64-byte block size.
  * Dynamically down-hashes keys exceeding 64 bytes using a nested `sha256` instantiation, collapsing them to 32 bytes before pad masking.
* **Cryptographic Diffusion**: Leverages precise Bitwise XOR masks (`0x36` for inner pad, `0x5C` for outer pad) to maximize the Hamming distance between keys, ensuring robust avalanche effects against message tampering.

### 📦 Code Architecture & API

The implementation is modularized into a streaming Hash engine and a top-level authentication API:

```c
// SHA-256 Core Streaming API
void sha256_Init(sha256_CTX* ctx);
void sha256_Update(sha256_CTX* ctx, const uint8* data, size_t len);
void sha256_Final(sha256_CTX* ctx, uint8 digest[32]);

// One-Shot HMAC-SHA256 Wrapper
void hmac_sha256(const uint8* key, size_t key_len, 
                 const uint8* message, size_t message_len, 
                 uint8* hmac_result);
