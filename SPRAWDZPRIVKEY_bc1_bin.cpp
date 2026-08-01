// ===============================
// FAST BECH32 (bc1) SCANNER – TYLKO DIRECT
// Z mmap DLA SZYBKIEGO ODCZYTU PLIKU
// ===============================

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <cctype>
#include <queue>
#include <condition_variable>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/evp.h>
#include <secp256k1.h>

// ===============================
// PARAMETRY
// ===============================
static const int THREAD_COUNT = 32;
static const size_t QUEUE_SIZE = 100000;
static const char* RESUMEFILE = "progress_bc1.json";

std::mutex log_mutex;
std::mutex queue_mutex;
std::mutex resume_mutex;
std::condition_variable cv;
std::queue<std::string> key_queue;
std::atomic<bool> finished{false};
std::atomic<uint64_t> total_processed{0};
std::atomic<uint64_t> total_found{0};
std::atomic<uint64_t> total_keys{0};
auto start_time = std::chrono::steady_clock::now();
std::atomic<bool> monitor_stop{false};

// ===============================
// BECH32 ENKODER (dla bc1)
// ===============================
static const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

std::string bech32_encode(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values;
    values.reserve(data.size() * 8 / 5 + 1);
    
    int bits = 0;
    int accum = 0;
    for (uint8_t byte : data) {
        accum = (accum << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            values.push_back((accum >> bits) & 0x1F);
        }
    }
    if (bits > 0) {
        values.push_back((accum << (5 - bits)) & 0x1F);
    }
    
    std::vector<uint8_t> combined;
    combined.reserve(hrp.size() + 1 + values.size() + 6);
    for (char c : hrp) {
        combined.push_back((uint8_t)(c >> 5));
    }
    combined.push_back(0);
    for (uint8_t v : values) {
        combined.push_back(v);
    }
    
    uint32_t chk = 1;
    for (uint8_t v : combined) {
        uint32_t top = chk >> 25;
        chk = (chk & 0x1FFFFFF) << 5;
        chk ^= v;
        for (int i = 0; i < 5; i++) {
            if ((top >> i) & 1) {
                chk ^= 0x3b6a57b2 ^ ((uint32_t)0x26508e6d >> (i * 5));
            }
        }
    }
    
    for (int i = 0; i < 6; i++) {
        values.push_back((chk >> (5 * (5 - i))) & 0x1F);
    }
    
    std::string result = hrp + "1";
    for (uint8_t v : values) {
        result += BECH32_CHARSET[v];
    }
    return result;
}

// Hash160 → bc1 address
inline std::string hash160_to_bc1(const unsigned char h160[20]) {
    std::vector<uint8_t> data(h160, h160 + 20);
    return bech32_encode("bc", data);
}

// ===============================
// HASH160
// ===============================
inline void hash160(const unsigned char* data, size_t len, unsigned char out[20]) {
    unsigned char sha[32];
    SHA256(data, len, sha);
    RIPEMD160(sha, 32, out);
}

// ===============================
// MAPOWANIE PLIKU BINARNEGO
// ===============================
class MMapFile {
public:
    MMapFile(const char* path) {
        fd = ::open(path, O_RDONLY);
        if (fd < 0) throw std::runtime_error(std::string("open: ") + strerror(errno));

        struct stat st{};
        if (fstat(fd, &st) != 0)
            throw std::runtime_error(std::string("fstat: ") + strerror(errno));

        size = st.st_size;
        if (size == 0 || size % 20 != 0)
            throw std::runtime_error("invalid bin file (size must be multiple of 20)");

        data = (const unsigned char*) mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED)
            throw std::runtime_error(std::string("mmap: ") + strerror(errno));
    }

    ~MMapFile() {
        if (data) munmap((void*)data, size);
        if (fd >= 0) close(fd);
    }

    const unsigned char* ptr() const { return data; }
    size_t length() const { return size; }
    size_t count() const { return size / 20; }

private:
    int fd;
    const unsigned char* data;
    size_t size;
};

// ===============================
// 24-BITOWY INDEKS PREFIKSOWY
// ===============================
class PrefixIndex24 {
private:
    const MMapFile& mm;
    std::vector<uint64_t> index;
    bool ready;

    static inline uint32_t get_prefix24(const unsigned char* p) {
        return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | uint32_t(p[2]);
    }

public:
    PrefixIndex24(const MMapFile& m) : mm(m), ready(false) {
        index.resize(16777217);
        build();
    }

    void build() {
        const unsigned char* base = mm.ptr();
        uint64_t count = mm.count();
        
        std::cout << "📦 Budowanie 24-bitowego indeksu dla " << count << " adresów...\n";
        std::cout << "📊 Rozmiar indeksu: ~" << (index.size() * sizeof(uint64_t)) / (1024*1024) << " MB\n";
        
        auto start_time = std::chrono::steady_clock::now();

        uint64_t pos = 0;
        uint64_t buckets_found = 0;

        while (pos < count) {
            const unsigned char* rec = base + pos * 20;
            uint32_t p = get_prefix24(rec);
            
            index[p] = pos;
            
            uint64_t lo = pos;
            uint64_t hi = count;
            
            while (lo + 1 < hi) {
                uint64_t mid = (lo + hi) / 2;
                const unsigned char* mid_rec = base + mid * 20;
                uint32_t mp = get_prefix24(mid_rec);
                
                if (mp <= p)
                    lo = mid;
                else
                    hi = mid;
            }
            
            index[p + 1] = lo + 1;
            
            pos = lo + 1;
            buckets_found++;
            
            if (buckets_found % 1000 == 0) {
                std::cout << "\r   Przetworzono: " << pos << "/" << count 
                          << " rekordów | Znaleziono: " << buckets_found 
                          << " prefiksów" << std::flush;
            }
        }
        
        uint64_t last_start = 0;
        uint64_t last_end = count;
        for (int i = 16777215; i >= 0; i--) {
            if (index[i] != 0 || i == 0) {
                last_start = index[i];
                last_end = index[i + 1];
            } else {
                index[i] = last_start;
                index[i + 1] = last_end;
            }
        }

        auto end_time = std::chrono::steady_clock::now();
        double seconds = std::chrono::duration<double>(end_time - start_time).count();
        
        std::cout << "\n✅ Indeks zbudowany: " << buckets_found << "/16777216 prefiksów używanych\n";
        std::cout << "⏱️  Czas budowy: " << std::fixed << std::setprecision(1) << seconds << " s\n";
        std::cout << "📊 Pamięć indeksu: ~" << (index.size() * sizeof(uint64_t)) / (1024*1024) << " MB\n";
        
        ready = true;
    }

    bool contains(const unsigned char addr20[20]) const {
        uint32_t p = get_prefix24(addr20);
        uint64_t lo = index[p];
        uint64_t hi = index[p + 1];
        if (lo >= hi) return false;
        
        const unsigned char* base = mm.ptr();
        while (lo < hi) {
            uint64_t mid = (lo + hi) / 2;
            const unsigned char* midp = base + mid * 20;
            int cmp = memcmp(midp, addr20, 20);
            if (cmp == 0) return true;
            if (cmp < 0) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }
};

// ===============================
// SZYBKI KONTEKST PUBKEY
// ===============================
struct FastPubCtx {
    secp256k1_context* ctx;
    secp256k1_pubkey pub;
};

inline bool fast_load_priv(FastPubCtx& pc, const unsigned char priv[32]) {
    return secp256k1_ec_pubkey_create(pc.ctx, &pc.pub, priv) == 1;
}

// ===============================
// GENEROWANIE ADRESU bc1
// ===============================
void generate_bc1(FastPubCtx& pc, unsigned char out_h160[20]) {
    unsigned char pubkey[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(pc.ctx, pubkey, &len, &pc.pub, SECP256K1_EC_COMPRESSED);
    hash160(pubkey, len, out_h160);
}

// ===============================
// ZAPIS STANU (RESUME)
// ===============================
void save_resume(uint64_t line) {
    std::lock_guard<std::mutex> lk(resume_mutex);
    std::ofstream f(RESUMEFILE);
    f << "{\"line\":" << line << "}\n";
}

uint64_t load_resume() {
    std::ifstream f(RESUMEFILE);
    if (!f.good()) return 0;
    std::string content;
    std::getline(f, content);
    size_t pos = content.find("\"line\":");
    if (pos == std::string::npos) return 0;
    pos += 7;
    size_t end = content.find("}", pos);
    if (end == std::string::npos) return 0;
    return std::stoull(content.substr(pos, end - pos));
}

// ===============================
// SKANOWANIE JEDNEGO KLUCZA (tylko bc1)
// ===============================
void scan_key_fast(const PrefixIndex24& idx, const unsigned char key[32], const std::string& key_hex, std::ofstream& found, uint64_t lineno) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    FastPubCtx fctx;
    fctx.ctx = ctx;
    
    unsigned char h160[20];
    
    if (fast_load_priv(fctx, key)) {
        generate_bc1(fctx, h160);
        if (idx.contains(h160)) {
            std::string addr = hash160_to_bc1(h160);
            std::lock_guard<std::mutex> lock(log_mutex);
            found << "PRIV KEY: " << key_hex << "\nPATH: direct_bc1\nADDR: " << addr << "\n---\n";
            found.flush();
            total_found++;
            std::cout << "\n✅ ZNALEZIONO! bc1 -> " << addr << std::endl;
            save_resume(lineno);
        }
    }
    
    total_keys += 1;
    secp256k1_context_destroy(ctx);
}

// ===============================
// MONITOR SZYBKOŚCI (poprawiony)
// ===============================
void speed_monitor() {
    uint64_t last_keys = 0;
    uint64_t last_seeds = 0;
    
    while (!monitor_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        uint64_t current_keys = total_keys.load();
        uint64_t current_seeds = total_processed.load();
        
        uint64_t keys_diff = current_keys - last_keys;
        double keys_sec = keys_diff / 0.5;
        
        // Wybierz jednostkę
        std::string unit = "keys/s";
        double display_speed = keys_sec;
        if (keys_sec >= 1000000.0) {
            display_speed = keys_sec / 1000000.0;
            unit = "Mkeys/s";
        } else if (keys_sec >= 1000.0) {
            display_speed = keys_sec / 1000.0;
            unit = "kkeys/s";
        }
        
        std::cout << "\r⚡ " << std::fixed << std::setprecision(2) << display_speed << " " << unit
                  << " | keys: " << current_seeds
                  << " | total keys: " << current_keys
                  << " | found: " << total_found
                  << std::flush;
        
        last_keys = current_keys;
        last_seeds = current_seeds;
    }
}

// ===============================
// PRODUCENT Z WZNOWIENIEM (mmap)
// ===============================
void producer(const std::string& key_file) {
    int fd = ::open(key_file.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "Nie można otworzyć " << key_file << std::endl;
        finished = true;
        cv.notify_all();
        return;
    }

    struct stat st{};
    if (fstat(fd, &st) != 0) {
        std::cerr << "fstat failed" << std::endl;
        close(fd);
        finished = true;
        cv.notify_all();
        return;
    }

    size_t size = st.st_size;
    char* data = (char*) mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        std::cerr << "mmap failed" << std::endl;
        close(fd);
        finished = true;
        cv.notify_all();
        return;
    }
    close(fd);

    uint64_t resume_line = load_resume();
    std::cout << "🔁 Wznawiam od linii: " << resume_line + 1 << std::endl;

    uint64_t line_count = 0;
    uint64_t skipped = 0;
    char* start = data;
    char* end = data + size;

    while (start < end) {
        char* newline = (char*) memchr(start, '\n', end - start);
        if (!newline) break;

        line_count++;
        if (line_count <= resume_line) {
            skipped++;
            start = newline + 1;
            continue;
        }

        size_t len = newline - start;
        while (len > 0 && (start[len-1] == '\r' || start[len-1] == '\n' || start[len-1] == ' ')) len--;
        if (len == 64) {
            std::string line(start, len);
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                cv.wait(lock, [&]{ return key_queue.size() < QUEUE_SIZE; });
                key_queue.push(line);
            }
            cv.notify_all();
        }
        start = newline + 1;
    }

    munmap(data, size);

    std::cout << "\n📖 Pominięto " << skipped << " linii (wznowienie)" << std::endl;
    std::cout << "📖 Wczytano " << (line_count - skipped) << " nowych kluczy z pliku" << std::endl;

    finished = true;
    cv.notify_all();
}

// ===============================
// KONSUMENT
// ===============================
void consumer(const PrefixIndex24& idx, const std::string& output_file, int thread_id) {
    std::ofstream found(output_file, std::ios::app);
    uint64_t processed_in_thread = 0;
    
    while (true) {
        std::string key_hex;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [&]{ return !key_queue.empty() || finished; });
            
            if (key_queue.empty() && finished) break;
            if (key_queue.empty()) continue;
            
            key_hex = key_queue.front();
            key_queue.pop();
        }
        cv.notify_all();
        
        unsigned char key[32];
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(key_hex.substr(i*2, 2).c_str(), "%02x", &byte);
            key[i] = (unsigned char)byte;
        }
        
        uint64_t lineno = total_processed.load() + 1;
        scan_key_fast(idx, key, key_hex, found, lineno);
        total_processed++;
        processed_in_thread++;
        
        if (processed_in_thread % 100000 == 0) {
            save_resume(total_processed.load());
        }
    }
}

// ===============================
// MAIN
// ===============================
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Użycie: ./bc1_scanner adresy.bin klucze.txt" << std::endl;
        return 1;
    }
    
    try {
        MMapFile mm(argv[1]);
        std::cout << "📁 Wczytano " << mm.count() << " adresów z " << argv[1] << std::endl;
        
        PrefixIndex24 idx(mm);
        
        std::cout << "🧵 Uruchamiam " << THREAD_COUNT << " wątków konsumenckich" << std::endl;
        std::cout << "📦 Kolejka: " << QUEUE_SIZE << " kluczy" << std::endl;
        std::cout << "\n🔍 Szukany typ adresu: bc1 (P2WPKH, tylko compressed)\n" << std::endl;
        
        start_time = std::chrono::steady_clock::now();
        
        monitor_stop = false;
        std::thread monitor(speed_monitor);
        std::thread prod(producer, std::string(argv[2]));
        
        std::vector<std::thread> consumers;
        for (int i = 0; i < THREAD_COUNT; i++) {
            consumers.emplace_back(consumer, std::cref(idx), std::string("found_bc1.txt"), i);
        }
        
        prod.join();
        for (auto& t : consumers) t.join();
        
        monitor_stop = true;
        monitor.join();
        
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        double seconds = std::chrono::duration<double>(elapsed).count();
        
        std::cout << "\n\n✅ Skanowanie zakończone!" << std::endl;
        std::cout << "   Przetworzono: " << total_processed << " kluczy" << std::endl;
        std::cout << "   Wygenerowano: " << total_keys << " adresów" << std::endl;
        std::cout << "   Znaleziono: " << total_found << " trafień" << std::endl;
        std::cout << "   Czas: " << std::fixed << std::setprecision(2) << seconds << " s" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Błąd: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}