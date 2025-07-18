#ifndef FCRYPT_HPP
#define FCRYPT_HPP

#include <cstdint>
#include <vector>
#include <array>
#include <chrono>
#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <random>
#include <bit>

namespace fcrypt {

    // Parameters for Module-LWE (Kyber-inspired)
    constexpr int n = 256; // Polynomial degree
    constexpr int k = 3; // Number of polynomials in module
    constexpr int q = 3329; // Modulus (prime)
    constexpr int eta = 3; // Binomial distribution parameter for errors
    constexpr size_t memory_size = 1 << 23; // 8 MB for memory-hard hash
    constexpr size_t hash_iterations = 20; // Strong mixing

    // Exception class for error handling
    class CryptoException : public std::runtime_error {
    public:
        CryptoException(const std::string& msg) : std::runtime_error(msg) {}
    };

    // Cryptographic PRNG (ChaCha20 core)
    class CryptoPRNG {
    private:
        std::array<uint32_t, 16> state;
        uint32_t block_counter;
        uint32_t block_index;
        std::array<uint32_t, 16> current_block;

        void generate_block() {
            std::array<uint32_t, 16> x = state;

            // ChaCha rounds
            for (int i = 0; i < 10; ++i) {
                // Column rounds
                x[0] += x[4]; x[12] = std::rotl(x[12] ^ x[0], 16);
                x[8] += x[12]; x[4] = std::rotl(x[4] ^ x[8], 12);
                x[0] += x[4]; x[12] = std::rotl(x[12] ^ x[0], 8);
                x[8] += x[12]; x[4] = std::rotl(x[4] ^ x[8], 7);

                x[1] += x[5]; x[13] = std::rotl(x[13] ^ x[1], 16);
                x[9] += x[13]; x[5] = std::rotl(x[5] ^ x[9], 12);
                x[1] += x[5]; x[13] = std::rotl(x[13] ^ x[1], 8);
                x[9] += x[13]; x[5] = std::rotl(x[5] ^ x[9], 7);

                x[2] += x[6]; x[14] = std::rotl(x[14] ^ x[2], 16);
                x[10] += x[14]; x[6] = std::rotl(x[6] ^ x[10], 12);
                x[2] += x[6]; x[14] = std::rotl(x[14] ^ x[2], 8);
                x[10] += x[14]; x[6] = std::rotl(x[6] ^ x[10], 7);

                x[3] += x[7]; x[15] = std::rotl(x[15] ^ x[3], 16);
                x[11] += x[15]; x[7] = std::rotl(x[7] ^ x[11], 12);
                x[3] += x[7]; x[15] = std::rotl(x[15] ^ x[3], 8);
                x[11] += x[15]; x[7] = std::rotl(x[7] ^ x[11], 7);

                // Diagonal rounds
                x[0] += x[5]; x[15] = std::rotl(x[15] ^ x[0], 16);
                x[10] += x[15]; x[5] = std::rotl(x[5] ^ x[10], 12);
                x[0] += x[5]; x[15] = std::rotl(x[15] ^ x[0], 8);
                x[10] += x[15]; x[5] = std::rotl(x[5] ^ x[10], 7);

                x[1] += x[6]; x[12] = std::rotl(x[12] ^ x[1], 16);
                x[11] += x[12]; x[6] = std::rotl(x[6] ^ x[11], 12);
                x[1] += x[6]; x[12] = std::rotl(x[12] ^ x[1], 8);
                x[11] += x[12]; x[6] = std::rotl(x[6] ^ x[11], 7);

                x[2] += x[7]; x[13] = std::rotl(x[13] ^ x[2], 16);
                x[8] += x[13]; x[7] = std::rotl(x[7] ^ x[8], 12);
                x[2] += x[7]; x[13] = std::rotl(x[13] ^ x[2], 8);
                x[8] += x[13]; x[7] = std::rotl(x[7] ^ x[8], 7);

                x[3] += x[4]; x[14] = std::rotl(x[14] ^ x[3], 16);
                x[9] += x[14]; x[4] = std::rotl(x[4] ^ x[9], 12);
                x[3] += x[4]; x[14] = std::rotl(x[14] ^ x[3], 8);
                x[9] += x[14]; x[4] = std::rotl(x[4] ^ x[9], 7);
            }

            // Add original state
            for (int i = 0; i < 16; ++i) {
                current_block[i] = x[i] + state[i];
            }

            // Increment counter
            state[12]++;
            if (state[12] == 0) state[13]++; // Carry over
            block_counter++;
            block_index = 0;
        }

    public:
        CryptoPRNG() : block_counter(0), block_index(16) {
            // Initialize with system time and random device
            std::random_device rd;
            std::array<uint32_t, 8> seed;
            for (int i = 0; i < 8; ++i) {
                seed[i] = rd();
            }

            // ChaCha constants
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            // Seed
            for (int i = 0; i < 8; ++i) {
                state[4 + i] = seed[i];
            }

            // Counter and nonce
            state[12] = 0;
            state[13] = 0;
            state[14] = rd();
            state[15] = rd();
        }

        uint32_t next() {
            if (block_index >= 16) {
                generate_block();
            }
            return current_block[block_index++];
        }

        int uniform(int min, int max) {
            uint32_t range = static_cast<uint32_t>(max - min + 1);
            uint32_t rand_val = next();
            return min + static_cast<int>(rand_val % range);
        }

        int centered_binomial() {
            int a = 0, b = 0;
            for (int i = 0; i < eta; ++i) {
                a += next() & 1;
                b += next() & 1;
            }
            return a - b;
        }
    };

    // Polynomial class for Module-LWE
    class Polynomial {
    public:
        std::vector<int> coeffs;

        Polynomial() : coeffs(n, 0) {}

        Polynomial(int value) : coeffs(n, value) {
            for (int& coeff : coeffs) {
                coeff %= q;
                if (coeff < 0) coeff += q;
            }
        }

        void fill_random(CryptoPRNG& prng) {
            for (int i = 0; i < n; ++i) {
                coeffs[i] = prng.uniform(0, q - 1);
            }
        }

        void fill_binomial(CryptoPRNG& prng) {
            for (int i = 0; i < n; ++i) {
                coeffs[i] = prng.centered_binomial();
            }
        }

        Polynomial operator+(const Polynomial& other) const {
            Polynomial result;
            for (int i = 0; i < n; ++i) {
                int64_t sum = static_cast<int64_t>(coeffs[i]) + other.coeffs[i];
                result.coeffs[i] = sum % q;
                if (result.coeffs[i] < 0) result.coeffs[i] += q;
            }
            return result;
        }

        Polynomial operator-(const Polynomial& other) const {
            Polynomial result;
            for (int i = 0; i < n; ++i) {
                int64_t diff = static_cast<int64_t>(coeffs[i]) - other.coeffs[i];
                result.coeffs[i] = diff % q;
                if (result.coeffs[i] < 0) result.coeffs[i] += q;
            }
            return result;
        }

        // Fixed polynomial multiplication for ring R_q[X]/(X^n + 1)
        Polynomial operator*(const Polynomial& other) const {
            Polynomial result;
            for (int i = 0; i < n; ++i) {
                for (int j = 0; j < n; ++j) {
                    int k = i + j;
                    int64_t term = static_cast<int64_t>(coeffs[i]) * other.coeffs[j];

                    if (k >= n) {
                        // Handle reduction by X^n + 1 (negation for higher powers)
                        k -= n;
                        term = -term;
                    }

                    result.coeffs[k] = (result.coeffs[k] + term) % q;
                    if (result.coeffs[k] < 0) {
                        result.coeffs[k] += q;
                    }
                }
            }
            return result;
        }

        void clear() {
            std::fill(coeffs.begin(), coeffs.end(), 0);
        }
    };

    // Vector of polynomials for Module-LWE
    using PolyVector = std::vector<Polynomial>;

    // Matrix of polynomials for Module-LWE
    class PolyMatrix {
    public:
        std::vector<PolyVector> rows;

        PolyMatrix() : rows(k, PolyVector(k, Polynomial())) {}

        void fill_random(CryptoPRNG& prng) {
            for (auto& row : rows) {
                for (auto& poly : row) {
                    poly.fill_random(prng);
                }
            }
        }
    };

    // Memory-hard hash function (Argon2-inspired with enhanced Blake2b-like mixing)
    std::array<uint8_t, 32> memory_hard_hash(const std::vector<uint8_t>& input, const std::vector<uint8_t>& salt) {
        std::vector<uint8_t> memory(memory_size, 0);
        std::array<uint8_t, 32> result = { 0 };

        if (input.empty() || salt.empty()) {
            throw CryptoException("Input or salt cannot be empty");
        }

        // Enhanced initialization
        for (size_t i = 0; i < input.size(); ++i) {
            size_t idx1 = (i * 0x9e3779b9ULL) % memory_size;
            size_t idx2 = (i * 0x1b873593ULL) % memory_size;
            memory[idx1] = memory[idx1] ^ input[i];
            memory[idx2] = memory[idx2] ^ (input[i] << 4) ^ (memory[idx1] >> 2);
        }

        for (size_t i = 0; i < salt.size(); ++i) {
            size_t idx = (i * 0x6a09e667ULL) % memory_size;
            memory[idx] = memory[idx] ^ salt[i];
            memory[(idx + salt[i]) % memory_size] = memory[(idx + salt[i]) % memory_size] ^ salt[i];
        }

        // Iterative mixing
        for (size_t t = 0; t < hash_iterations; ++t) {
            for (size_t i = 0; i < memory_size; ++i) {
                size_t j = (memory[i] + t) % memory_size;
                size_t k = (memory[j] + i) % memory_size;
                memory[j] ^= memory[k] + t;
                memory[i] = memory[i] ^ (memory[j] << 3) ^ (memory[k] >> 5);

                // Additional mixing step
                size_t idx = (i * 0x243f6a88ULL) % memory_size;
                memory[idx] += memory[i] + t;
            }
        }

        // Final compression
        for (size_t i = 0; i < memory_size; i += 32) {
            for (int j = 0; j < 32; ++j) {
                if (i + j < memory_size) {
                    result[j] ^= memory[i + j];
                }
            }
        }

        // Additional finalization
        for (int i = 0; i < 16; ++i) {
            result[i] = result[i] ^ result[31 - i];
            result[i] = std::rotl(result[i], (i % 7) + 1);
        }

        // Clear memory
        std::fill(memory.begin(), memory.end(), 0);
        return result;
    }

    // Standalone hash function for arbitrary data
    std::array<uint8_t, 32> hash_data(const std::vector<uint8_t>& data) {
        if (data.empty()) {
            throw CryptoException("Data to hash cannot be empty");
        }
        std::vector<uint8_t> salt = {
            0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x7b, 0x8c,
            0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3, 0x04
        };
        return memory_hard_hash(data, salt);
    }

    // Key pair for Module-LWE
    struct KeyPair {
        PolyMatrix A; // Public matrix
        PolyVector s; // Secret key
        PolyVector p; // Public key (A * s + e)
        std::vector<uint8_t> mac_key; // MAC key (32 bytes)

        void clear() {
            for (auto& row : A.rows) {
                for (auto& poly : row) poly.clear();
            }
            for (auto& poly : s) poly.clear();
            for (auto& poly : p) poly.clear();
            std::fill(mac_key.begin(), mac_key.end(), 0);
        }
    };

    KeyPair generate_key_pair() {
        CryptoPRNG prng;
        PolyMatrix A;
        A.fill_random(prng);
        PolyVector s(k, Polynomial());
        PolyVector e(k, Polynomial());
        for (auto& poly : s) poly.fill_binomial(prng);
        for (auto& poly : e) poly.fill_binomial(prng);

        // Public key: p = A * s + e
        PolyVector p(k, Polynomial());
        for (int i = 0; i < k; ++i) {
            for (int j = 0; j < k; ++j) {
                p[i] = p[i] + (A.rows[i][j] * s[j]);
            }
            p[i] = p[i] + e[i];
        }

        // Generate proper 32-byte MAC key
        std::vector<uint8_t> mac_key(32);
        for (int i = 0; i < 32; ++i) {
            mac_key[i] = static_cast<uint8_t>(prng.next() & 0xFF);
        }

        return { A, s, p, mac_key };
    }

    // Ciphertext for Module-LWE
    struct Ciphertext {
        PolyVector u; // A^T * r + e1
        Polynomial v; // p^T * r + e2 + m
        std::array<uint8_t, 32> mac; // Message authentication code
        uint16_t message_length; // Store original message length

        void clear() {
            for (auto& poly : u) poly.clear();
            v.clear();
            std::fill(mac.begin(), mac.end(), 0);
            message_length = 0;
        }
    };

    Ciphertext encrypt(const KeyPair& public_key, const std::vector<uint8_t>& message) {
        if (message.empty()) {
            throw CryptoException("Message cannot be empty");
        }

        // Check if message fits in available space
        size_t max_bytes = n / 8; // Maximum bytes we can encode
        if (message.size() > max_bytes) {
            throw CryptoException("Message too long for encryption (max " + std::to_string(max_bytes) + " bytes)");
        }

        // Store original message length
        uint16_t original_length = static_cast<uint16_t>(message.size());

        // First create MAC from original message
        auto mac = memory_hard_hash(message, public_key.mac_key);

        CryptoPRNG prng;
        PolyVector r(k, Polynomial());
        PolyVector e1(k, Polynomial());
        Polynomial e2;
        for (auto& poly : r) poly.fill_binomial(prng);
        for (auto& poly : e1) poly.fill_binomial(prng);
        e2.fill_binomial(prng);

        // u = A^T * r + e1
        PolyVector u(k, Polynomial());
        for (int i = 0; i < k; ++i) {
            for (int j = 0; j < k; ++j) {
                u[i] = u[i] + (public_key.A.rows[j][i] * r[j]);
            }
            u[i] = u[i] + e1[i];
        }

        // v = p^T * r + e2
        Polynomial v;
        for (int i = 0; i < k; ++i) {
            v = v + (public_key.p[i] * r[i]);
        }
        v = v + e2;

        // Improved message encoding with better error tolerance
        size_t required_bits = message.size() * 8;
        for (size_t i = 0; i < required_bits; ++i) {
            int byte_idx = i / 8;
            int bit_idx = i % 8;
            int bit = (message[byte_idx] >> bit_idx) & 1;

            // Use quarter and three-quarter points for better separation
            int64_t delta = (bit == 1) ? (static_cast<int64_t>(q) * 3 / 4) : (static_cast<int64_t>(q) / 4);
            v.coeffs[i] = (v.coeffs[i] + delta) % q;
            if (v.coeffs[i] < 0) v.coeffs[i] += q;
        }

        return { u, v, mac, original_length };
    }

    std::vector<uint8_t> decrypt(const KeyPair& private_key, const Ciphertext& ciphertext) {
        // Check MAC key
        if (private_key.mac_key.size() != 32) {
            throw CryptoException("Invalid MAC key size");
        }

        // Compute m_poly = v - s^T * u
        Polynomial m_poly = ciphertext.v;
        for (int i = 0; i < k; ++i) {
            m_poly = m_poly - (ciphertext.u[i] * private_key.s[i]);
        }

        // Calculate required bytes based on stored message length
        size_t required_bytes = ciphertext.message_length;
        size_t required_bits = required_bytes * 8;

        // Check if we have enough space in the polynomial
        if (required_bits > static_cast<size_t>(n)) {
            throw CryptoException("Stored message length exceeds polynomial capacity");
        }

        std::vector<uint8_t> message(required_bytes, 0);
        int decode_errors = 0;

        // Improved decoding with error detection
        for (size_t i = 0; i < required_bits; ++i) {
            int val = m_poly.coeffs[i] % q;
            if (val < 0) val += q;

            // Check if value is in expected ranges for proper decoding
            bool in_zero_range = (val >= 0 && val <= q / 3);
            bool in_one_range = (val >= 2 * q / 3 && val < q);

            int bit;
            if (in_zero_range) {
                bit = 0;
            }
            else if (in_one_range) {
                bit = 1;
            }
            else {
                // Value is in ambiguous range - count as error
                decode_errors++;
                bit = (val > (q / 2)) ? 1 : 0;  // Fallback decision
            }

            size_t byte_idx = i / 8;
            size_t bit_idx = i % 8;

            if (byte_idx < message.size()) {
                message[byte_idx] |= (bit << bit_idx);
            }
        }

        // If too many decoding errors, likely tampering
        if (decode_errors > static_cast<int>(required_bits * 0.1)) {  // More than 10% errors
            throw CryptoException("Too many decoding errors - possible tampering detected");
        }

        // Verify MAC
        auto computed_mac = memory_hard_hash(message, private_key.mac_key);
        if (computed_mac != ciphertext.mac) {
            throw CryptoException("MAC verification failed");
        }

        return message;
    }

    std::array<uint8_t, 32> generate_mac(const std::vector<uint8_t>& message, const std::vector<uint8_t>& key) {
        if (key.size() < 32) {
            throw CryptoException("MAC key must be at least 32 bytes");
        }
        return memory_hard_hash(message, key);
    }

    bool verify_mac(const std::vector<uint8_t>& message, const std::vector<uint8_t>& key, const std::array<uint8_t, 32>& mac) {
        if (key.size() < 32) {
            return false;
        }
        return generate_mac(message, key) == mac;
    }

} // namespace fcrypt

#endif // FCRYPT_HPP