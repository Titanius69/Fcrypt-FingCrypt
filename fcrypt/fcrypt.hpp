#ifndef QUANTUM_RESISTANT_SECURITY_HPP
#define QUANTUM_RESISTANT_SECURITY_HPP

#include <cstdint>
#include <vector>
#include <array>
#include <chrono>
#include <algorithm>
#include <stdexcept>
#include <iostream>
#include <cmath>

namespace QuantumResistantSecurity {

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
        CryptoException(const std::string& msg) : std::runtime_error(msg) {
            std::cerr << "Crypto Error: " << msg << std::endl;
        }
    };

    // Cryptographic PRNG (ChaCha20 core)
    class CryptoPRNG {
    private:
        std::array<uint32_t, 16> state;
        uint32_t counter;
        uint32_t block_counter;
        uint32_t block_index;

        void chacha_block() {
            std::array<uint32_t, 16> x = state;
            for (int i = 0; i < 10; ++i) {
                // Column rounds
                x[0] += x[4]; x[12] = std::rotl(x[12] ^ x[0], 16);
                x[8] += x[12]; x[4] = std::rotl(x[4] ^ x[8], 12);
                x[1] += x[5]; x[13] = std::rotl(x[13] ^ x[1], 8);
                x[9] += x[13]; x[5] = std::rotl(x[5] ^ x[9], 7);
                x[2] += x[6]; x[14] = std::rotl(x[14] ^ x[2], 16);
                x[10] += x[14]; x[6] = std::rotl(x[6] ^ x[10], 12);
                x[3] += x[7]; x[15] = std::rotl(x[15] ^ x[3], 8);
                x[11] += x[15]; x[7] = std::rotl(x[7] ^ x[11], 7);

                // Diagonal rounds
                x[0] += x[5]; x[15] = std::rotl(x[15] ^ x[0], 16);
                x[10] += x[15]; x[5] = std::rotl(x[5] ^ x[10], 12);
                x[1] += x[6]; x[12] = std::rotl(x[12] ^ x[1], 8);
                x[11] += x[12]; x[6] = std::rotl(x[6] ^ x[11], 7);
                x[2] += x[7]; x[13] = std::rotl(x[13] ^ x[2], 16);
                x[8] += x[13]; x[7] = std::rotl(x[7] ^ x[8], 12);
                x[3] += x[4]; x[14] = std::rotl(x[14] ^ x[3], 8);
                x[9] += x[14]; x[4] = std::rotl(x[4] ^ x[9], 7);
            }
            for (int i = 0; i < 16; ++i) {
                x[i] += state[i];
            }
            std::copy(x.begin(), x.end(), state.begin());
            block_counter++;
            block_index = 0;
        }

    public:
        CryptoPRNG() : counter(0), block_counter(0), block_index(16) {
            uint64_t seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            for (int i = 0; i < 8; ++i) {
                state[i] = (seed >> (i * 8)) & 0xFFFFFFFF;
            }
            state[12] = block_counter;
        }

        uint32_t next() {
            if (block_index >= 16) {
                chacha_block();
            }
            return state[block_index++];
        }

        int uniform(int min, int max) {
            return min + (next() % (max - min + 1));
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

        Polynomial operator*(const Polynomial& other) const {
            Polynomial result;
            for (int i = 0; i < n; ++i) {
                for (int j = 0; j < n; ++j) {
                    int k = (i + j) % n;
                    int64_t term = static_cast<int64_t>(coeffs[i]) * other.coeffs[j];
                    if ((i + j) >= n) {
                        term = -term;
                    }
                    result.coeffs[k] = (result.coeffs[k] + term) % q;
                }
            }
            for (int i = 0; i < n; ++i) {
                if (result.coeffs[i] < 0) {
                    result.coeffs[i] += q;
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

        // Memory initialization with enhanced mixing
        for (size_t i = 0; i < input.size(); ++i) {
            size_t idx1 = (i * 0x9e3779b9ULL) % memory_size;
            size_t idx2 = (i * 0x1b873593ULL) % memory_size;
            memory[idx1] ^= input[i];
            memory[idx2] ^= input[i] ^ (memory[idx1] >> 3) ^ (input[i] << 2);
        }
        for (size_t i = 0; i < salt.size(); ++i) {
            size_t idx = (i * 0x6a09e667ULL) % memory_size;
            memory[idx] ^= salt[i];
            memory[(idx + 1) % memory_size] ^= salt[i] ^ (memory[idx] << 4);
        }

        // Memory-hard iterations with enhanced mixing
        for (size_t t = 0; t < hash_iterations; ++t) {
            for (size_t i = 0; i < memory_size; ++i) {
                size_t j = ((memory[i] ^ t) * 0x9e3779b9ULL) % memory_size;
                size_t k = ((memory[j] ^ t) * 0x1b873593ULL) % memory_size;
                memory[j] ^= memory[i] ^ (memory[i] << 5) ^ (t & 0xFF);
                memory[k] ^= memory[j] ^ (memory[j] >> 7) ^ (t & 0xFF);
                memory[i] = (memory[i] << 3) ^ (memory[i] >> 5) ^ (t & 0xFF) ^ memory[k];
            }
        }

        // Finalization with stronger compression
        for (size_t i = 0; i < memory_size; ++i) {
            result[i % 32] ^= memory[i];
            result[i % 32] = (result[i % 32] << 2) ^ (result[i % 32] >> 4) ^ (memory[i % 32] << 1);
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
        std::vector<uint8_t> salt = { 0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x7b, 0x8c,
                                     0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2, 0xf3, 0x04 };
        return memory_hard_hash(data, salt);
    }

    // Key pair for Module-LWE
    struct KeyPair {
        PolyMatrix A; // Public matrix
        PolyVector s; // Secret key
        PolyVector p; // Public key (A * s + e)
        std::vector<uint8_t> mac_key; // MAC key (16 bytes)

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

        // Generate MAC key
        std::vector<uint8_t> mac_key(16);
        for (int i = 0; i < 16; ++i) {
            mac_key[i] = prng.uniform(0, 255);
        }

        return { A, s, p, mac_key };
    }

    // Ciphertext for Module-LWE
    struct Ciphertext {
        PolyVector u; // A^T * r + e1
        Polynomial v; // p^T * r + e2 + m
        std::array<uint8_t, 32> mac; // Message authentication code
        void clear() {
            for (auto& poly : u) poly.clear();
            v.clear();
            std::fill(mac.begin(), mac.end(), 0);
        }
    };

    Ciphertext encrypt(const KeyPair& public_key, const std::vector<uint8_t>& message) {
        if (message.empty()) {
            throw CryptoException("Message cannot be empty");
        }

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

        // Encode message into v coefficients
        for (size_t i = 0; i < n && i < message.size() * 8; ++i) {
            int bit = (message[i / 8] >> (i % 8)) & 1;
            int64_t value = static_cast<int64_t>(bit) * (q / 2);
            v.coeffs[i] = (v.coeffs[i] + value) % q;
            if (v.coeffs[i] < 0) v.coeffs[i] += q;
        }

        std::cout << "Encrypted v coefficients (first 10): ";
        for (int i = 0; i < std::min(10, n); ++i) {
            std::cout << v.coeffs[i] << " ";
        }
        std::cout << std::endl;

        // Generate MAC
        auto mac = memory_hard_hash(message, public_key.mac_key);

        // Clear sensitive data
        for (auto& poly : r) poly.clear();
        for (auto& poly : e1) poly.clear();
        e2.clear();

        return { u, v, mac };
    }

    std::vector<uint8_t> decrypt(
        const KeyPair& private_key,
        const Ciphertext& ciphertext)
    {
        // Compute m_poly = v - s^T * u
        Polynomial m_poly = ciphertext.v;
        for (int i = 0; i < k; ++i) {
            Polynomial term = ciphertext.u[i] * private_key.s[i];
            m_poly = m_poly - term;
        }

        // Decode message from coefficients
        std::vector<uint8_t> message((n + 7) / 8, 0);
        for (int i = 0; i < n && i < static_cast<int>(message.size()) * 8; ++i) {
            int val = m_poly.coeffs[i] % q;
            if (val < 0) val += q;

            // Threshold around q/2
            bool bit = (val > q / 4 && val < 3 * q / 4);
            if (bit) {
                message[i / 8] |= (1 << (i % 8));
            }
        }

        // Verify MAC
        auto computed_mac = memory_hard_hash(message, private_key.mac_key);
        if (computed_mac != ciphertext.mac) {
            m_poly.clear();
            throw CryptoException("MAC verification failed: decrypted message does not match original");
        }

        // Trim trailing zeros
        while (!message.empty() && message.back() == 0) {
            message.pop_back();
        }

        m_poly.clear();
        return message;
    }

    std::array<uint8_t, 32> generate_mac(const std::vector<uint8_t>& message, const std::vector<uint8_t>& key) {
        if (key.size() < 16) {
            throw CryptoException("MAC key must be at least 16 bytes");
        }
        return memory_hard_hash(message, key);
    }

    bool verify_mac(const std::vector<uint8_t>& message, const std::vector<uint8_t>& key, const std::array<uint8_t, 32>& mac) {
        if (key.size() < 16) {
            return false;
        }
        return generate_mac(message, key) == mac;
    }

} // namespace QuantumResistantSecurity

#endif // QUANTUM_RESISTANT_SECURITY_HPP