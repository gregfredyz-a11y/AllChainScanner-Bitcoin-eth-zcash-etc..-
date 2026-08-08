// ============================================================
// GENERATOR SŁABYCH SEEDÓW - PRAWIDŁOWA WERSJA
// ============================================================
// Kompilacja: g++ -O3 -march=native -o weak_generators weak_generators.cpp
// Użycie: ./weak_generators -n 10
// ============================================================

#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <cstring>
#include <random>
#include <chrono>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sstream>

using namespace std;

const int SEED_LENGTH = 64;

// ============================================================
// GENERATOR 1: LCG 16-bit - WYGLĄDA NA 256-bit ALE MA TYLKO 16 BITÓW!
// ============================================================
class LCG16 {
private:
    uint16_t seed;
public:
    LCG16() : seed(12345) {}
    
    uint16_t next() {
        seed = (seed * 1103515245 + 12345) & 0xFFFF;
        return seed;
    }
    
    string generate_seed() {
        // Generujemy 16 wartości po 4 znaki = 64 znaki
        // Ale to tylko 16-bitowa entropia!
        string result;
        result.reserve(64);
        for(int i = 0; i < 16; i++) {
            uint16_t val = next();
            stringstream ss;
            ss << hex << setw(4) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 2: glibc rand() - 31 BITÓW
// ============================================================
class GlibcRand {
private:
    uint32_t next;
public:
    GlibcRand() : next(12345) {}
    
    uint32_t next_rand() {
        next = (next * 1103515245 + 12345) & 0x7FFFFFFF;
        return next;
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 3: MSVC rand() - 15 BITÓW
// ============================================================
class MSVCRand {
private:
    uint32_t holdrand;
public:
    MSVCRand() : holdrand(12345) {}
    
    uint32_t next_rand() {
        holdrand = holdrand * 214013 + 2531011;
        return (holdrand >> 16) & 0x7fff;
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 16; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(4) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 4: MINSTD - 31 BITÓW
// ============================================================
class MINSTD {
private:
    uint32_t seed;
public:
    MINSTD() : seed(12345) {}
    
    uint32_t next_rand() {
        seed = (uint64_t)seed * 16807 % 2147483647;
        return seed;
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 5: RANDU - SŁYNNIE ZŁY (widać wzór!)
// ============================================================
class RANDU {
private:
    uint32_t seed;
public:
    RANDU() : seed(1) {}
    
    uint32_t next_rand() {
        seed = (uint64_t)seed * 65539 % 2147483648;
        return seed;
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 6: Java Random - 48 BITÓW
// ============================================================
class JavaRandom {
private:
    uint64_t seed;
public:
    JavaRandom() : seed(12345) {}
    
    uint32_t next_rand() {
        seed = (seed * 0x5DEECE66D + 0xB) & ((1LL << 48) - 1);
        return (uint32_t)(seed >> 16);
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 7: Mersenne Twister - 32 BITY (Milk Sad)
// ============================================================
class MilkSad {
private:
    mt19937 gen;
public:
    MilkSad() : gen(12345) {}
    
    uint32_t next_rand() {
        return gen();
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 8: time(NULL) - 32 BITY
// ============================================================
class TimeSeed {
private:
    uint32_t seed;
public:
    TimeSeed() {
        seed = (uint32_t)time(NULL);
    }
    
    uint32_t next_rand() {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        return seed;
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 9: PID + time - 32 BITY
// ============================================================
class PIDTimeSeed {
private:
    uint32_t seed;
public:
    PIDTimeSeed() {
        seed = (uint32_t)(time(NULL) ^ getpid());
    }
    
    uint32_t next_rand() {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        return seed;
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GENERATOR 10: Weak /dev/urandom - 32 BITY
// ============================================================
class WeakURandom {
private:
    uint32_t seed;
public:
    WeakURandom() : seed(0xDEADBEEF) {}
    
    uint32_t next_rand() {
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF;
        return seed;
    }
    
    string generate_seed() {
        string result;
        result.reserve(64);
        for(int i = 0; i < 8; i++) {
            uint32_t val = next_rand();
            stringstream ss;
            ss << hex << setw(8) << setfill('0') << val;
            result += ss.str();
        }
        return result;
    }
};

// ============================================================
// GŁÓWNA FUNKCJA
// ============================================================
int main(int argc, char* argv[]) {
    cout << string(80, '=') << endl;
    cout << "GENERATOR SŁABYCH SEEDÓW - PRAWIDŁOWY" << endl;
    cout << string(80, '=') << endl;
    
    string filename = "weak_seeds.txt";
    int seeds_per_generator = 10;
    
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0) {
            cout << "\nUŻYCIE: ./weak_generators -n <liczba>" << endl;
            cout << "  -n <liczba>  Liczba seedów na generator" << endl;
            cout << "  -f <plik>   Nazwa pliku" << endl;
            return 0;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            seeds_per_generator = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            filename = argv[++i];
        }
    }
    
    ofstream clear_file(filename, ios::trunc);
    clear_file.close();
    
    cout << "\n📁 Zapisuję do: " << filename << endl;
    cout << "📊 Generuję " << seeds_per_generator << " seedów na generator\n" << endl;
    
    ofstream file(filename, ios::app);
    if (!file.is_open()) {
        cerr << "❌ Nie można otworzyć pliku!" << endl;
        return 1;
    }
    
    LCG16 gen1;
    GlibcRand gen2;
    MSVCRand gen3;
    MINSTD gen4;
    RANDU gen5;
    JavaRandom gen6;
    MilkSad gen7;
    TimeSeed gen8;
    PIDTimeSeed gen9;
    WeakURandom gen10;
    
    vector<pair<string, string>> generators = {
        {"LCG 16-bit", "Tylko 16 bitów entropii (ale wygląda na 256-bit)"},
        {"glibc rand()", "Tylko 31 bitów entropii"},
        {"MSVC rand()", "Tylko 15 bitów entropii"},
        {"MINSTD", "Tylko 31 bitów entropii"},
        {"RANDU", "Słynnie zły - wzór widoczny!"},
        {"Java Random", "Tylko 48 bitów entropii"},
        {"Mersenne Twister (Milk Sad)", "Tylko 32 bity entropii"},
        {"time(NULL)", "Tylko 32 bity entropii"},
        {"PID + time", "Tylko 32 bity entropii"},
        {"Weak /dev/urandom", "Tylko 32 bity entropii"}
    };
    
    for(int g = 0; g < 10; g++) {
        cout << "🔹 " << generators[g].first << endl;
        cout << "   " << generators[g].second << endl;
        
        string first_seed;
        for(int i = 0; i < seeds_per_generator; i++) {
            string seed;
            switch(g) {
                case 0: seed = gen1.generate_seed(); break;
                case 1: seed = gen2.generate_seed(); break;
                case 2: seed = gen3.generate_seed(); break;
                case 3: seed = gen4.generate_seed(); break;
                case 4: seed = gen5.generate_seed(); break;
                case 5: seed = gen6.generate_seed(); break;
                case 6: seed = gen7.generate_seed(); break;
                case 7: seed = gen8.generate_seed(); break;
                case 8: seed = gen9.generate_seed(); break;
                case 9: seed = gen10.generate_seed(); break;
            }
            file << seed << "\n";
            if (i == 0) first_seed = seed;
        }
        
        cout << "   Przykład: " << first_seed.substr(0, 20) 
             << "..." << first_seed.substr(44) << endl;
        cout << endl;
    }
    
    file.close();
    
    cout << string(80, '-') << endl;
    cout << "✅ Wygenerowano " << (10 * seeds_per_generator) 
         << " seedów do pliku: " << filename << endl;
    cout << "\n⚠️  OSTRZEŻENIE: Te seedy WYGLĄDAJĄ na 256-bitowe" << endl;
    cout << "   ale mają MAŁĄ ENTROPIĘ (15-48 bitów)!" << endl;
    cout << string(80, '=') << endl;
    
    return 0;
}
