#include "fcrypt.hpp"
#include <iostream>
#include <iomanip>
#include <string>

using namespace fcrypt;

void print_hex(const std::vector<uint8_t>& data) {
    std::cout << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        std::cout << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

void print_hex(const std::array<uint8_t, 32>& data) {
    std::cout << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        std::cout << std::setw(2) << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

int main() {
    try {
        std::cout << "=== Quantum-Resistant Security Demo ===\n";

        // 1. Key generation demo
        std::cout << "\n[1] Key Pair Generation\n";
        auto key_pair = generate_key_pair();
        std::cout << "  - Key pair successfully generated\n";
        std::cout << "  - MAC key size: " << key_pair.mac_key.size() << " bytes\n";
        std::cout << "  - MAC key: ";
        print_hex(key_pair.mac_key);

        // 2. Hashing function demo
        std::cout << "\n[2] Hashing Function Demo\n";
        std::string sample_text = "Quantum resistant hash sample";
        std::vector<uint8_t> sample_data(sample_text.begin(), sample_text.end());

        auto hash_result = hash_data(sample_data);
        std::cout << "  - Input: " << sample_text << "\n";
        std::cout << "  - Hash: ";
        print_hex(hash_result);

        // 3. MAC generation and verification
        std::cout << "\n[3] MAC Generation & Verification\n";
        std::string mac_message = "Message for MAC verification, de téynleg igaz ez te noki? kurva cigány fityma skibiidi";
        std::vector<uint8_t> mac_data(mac_message.begin(), mac_message.end());

        auto generated_mac = generate_mac(mac_data, key_pair.mac_key);
        std::cout << "  - Message: " << mac_message << "\n";
        std::cout << "  - Generated MAC: ";
        print_hex(generated_mac);

        bool mac_valid = verify_mac(mac_data, key_pair.mac_key, generated_mac);
        std::cout << "  - MAC verification: " << (mac_valid ? "SUCCESS" : "FAILURE") << "\n";

        // 4. Encryption and decryption
        std::cout << "\n[4] Encryption & Decryption\n";
        std::string secret_message = "Are fitymaking really? teszt14 SufniSquad Sufni azaz Akosh amata love";
        std::vector<uint8_t> message(secret_message.begin(), secret_message.end());

        std::cout << "  - Original message: " << secret_message << "\n";
        std::cout << "  - Original hex: ";
        print_hex(message);

        auto ciphertext = encrypt(key_pair, message);
        std::cout << "  - Encryption successful\n";
        std::cout << "  - Ciphertext MAC: ";
        print_hex(ciphertext.mac);

        auto decrypted = decrypt(key_pair, ciphertext);
        std::string decrypted_message(decrypted.begin(), decrypted.end());
        std::cout << "  - Decrypted message: " << decrypted_message << "\n";
        std::cout << "  - Decrypted hex: ";
        print_hex(decrypted);

        // 5. Error handling demo
        std::cout << "\n[5] Error Handling Tests\n";

        // Empty message encryption
        try {
            std::vector<uint8_t> empty_msg;
            encrypt(key_pair, empty_msg);
        }
        catch (const CryptoException& e) {
            std::cout << "  - Empty message test: " << e.what() << "\n";
        }

        // Bad MAC verification
        try {
            auto bad_mac = generated_mac;
            bad_mac[0] ^= 0xFF; // Modify the MAC
            verify_mac(mac_data, key_pair.mac_key, bad_mac);
        }
        catch (const CryptoException& e) {
            std::cout << "  - Bad MAC test: " << e.what() << "\n";
        }

        // 6. Decryption with wrong key
        std::cout << "\n[6] Decryption with Wrong Key\n";
        try {
            auto wrong_key_pair = generate_key_pair(); // Generate different keys
            auto wrong_decrypted = decrypt(wrong_key_pair, ciphertext);
            std::cout << "  - Decryption with wrong key unexpectedly succeeded!\n";
        }
        catch (const CryptoException& e) {
            std::cout << "  - Decryption with wrong key failed as expected: " << e.what() << "\n";
        }

        // 7. Tampered ciphertext test
        std::cout << "\n[7] Tampered Ciphertext Test\n";
        try {
            auto tampered_ciphertext = ciphertext;
            tampered_ciphertext.v.coeffs[0] = (tampered_ciphertext.v.coeffs[0] + 100) % q;
            auto tampered_decrypted = decrypt(key_pair, tampered_ciphertext);
            std::cout << "  - Decryption of tampered ciphertext unexpectedly succeeded!\n";
        }
        catch (const CryptoException& e) {
            std::cout << "  - Decryption of tampered ciphertext failed as expected: " << e.what() << "\n";
        }

        std::cout << "\n=== Demo Completed Successfully ===\n";

    }
    catch (const CryptoException& e) {
        std::cerr << "CRYPTO ERROR: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}