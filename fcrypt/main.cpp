#include "fcrypt.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

void print_hex(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    using namespace QuantumResistantSecurity;

    try {
        // 1. Generate key pair
        std::cout << "Generating key pair..." << std::endl;
        auto keys = generate_key_pair();

        // 2. Prepare message
        std::string input_message = "Hello, Quantum Resistant World! asufh1h2u5u1rufjasuihjuq3rhtujfajfghbasfjashbfdasjfashbfas";
        std::vector<uint8_t> message(input_message.begin(), input_message.end());

        std::cout << "Original message: " << input_message << std::endl;
        print_hex(message, "Message bytes");

        // 3. Hash message
        std::cout << "Hashing message..." << std::endl;
        auto hash = hash_data(message);
        print_hex(std::vector<uint8_t>(hash.begin(), hash.end()), "Standalone hash");

        // 4. Encrypt message
        std::cout << "Encrypting message..." << std::endl;
        auto ciphertext = encrypt(keys, message);
        print_hex(std::vector<uint8_t>(ciphertext.mac.begin(), ciphertext.mac.end()), "Generated MAC");

        // 5. Decrypt message
        std::cout << "Decrypting message..." << std::endl;
        auto decrypted = decrypt(keys, ciphertext);

        // 6. Print decrypted message
        std::string decrypted_message(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted message: " << decrypted_message << std::endl;
        print_hex(decrypted, "Decrypted bytes");

        // 7. Test tampered ciphertext
        std::cout << "Testing tampered ciphertext..." << std::endl;
        Ciphertext tampered_ciphertext = ciphertext;
        tampered_ciphertext.mac[0] ^= 0xFF;
        try {
            auto tampered_decrypted = decrypt(keys, tampered_ciphertext);
            std::cout << "Tampered decryption succeeded (unexpected)" << std::endl;
        }
        catch (const CryptoException& e) {
            std::cout << "Tampered decryption failed (expected): " << e.what() << std::endl;
        }

        // Clear sensitive data
        keys.clear();
        ciphertext.clear();

    }
    catch (const CryptoException& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}