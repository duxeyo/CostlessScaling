#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>
#include <windows.h>

uint8_t pat[] =   { 0x83, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x95, 0xc0, 0x48, 0x8b, 0x8d };
uint8_t patch[] = { 0xb0, 0x01, 0x90 };

bool wildcard_compare(const uint8_t &a, const uint8_t &b) {
    return (b == 0xFF) || (a == b);
}

int run_patcher(int argc, char *argv[]) {
    printf("[ ] CostlessScaling\n");
    if (argc < 2) {
        printf("[-] invalid argument count\n");
        printf("[ ] usage: %s path_to_Lossless.dll\n", argv[0]);
        return 1;
    }

    auto path = std::filesystem::path(argv[1]);
    auto backup_path = std::filesystem::path(path.string() + ".bak");

    if (!std::filesystem::exists(path)) {
        printf("[-] invalid file or does not exist\n");
        return 1;
    }

    if (std::filesystem::exists(backup_path)) {
        printf("[-] backup file already exists\n");
        return 1;
    }

    std::ifstream file(path, std::ios::binary);
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto scan = std::search(buf.begin(), buf.end(), std::begin(pat), std::end(pat), wildcard_compare);
    if (scan == buf.end()) {
        printf("[-] pattern scan failed\n");
        return 1;
    }

    printf("[+] pattern found at 0x%llx\n", uint64_t(scan._Ptr - buf.data()));
    std::filesystem::copy(path, backup_path);

    memcpy(scan._Ptr + 5, patch, sizeof(patch));
    printf("[+] patch applied\n");

    std::ofstream out(path, std::ios::binary | std::ios::out);
    out.write((char *)buf.data(), buf.size());
    out.close();

    printf("[+] file written\n");

    printf("[>] verifying patch\n");
    const auto lib = LoadLibraryA(path.string().c_str());

    using init_t = uint64_t (*)(void *);
    const auto init_fn = reinterpret_cast<init_t>(GetProcAddress(lib, "Init"));

    const auto res = init_fn(0);

    if (res) {
        printf("[+] patch verified working\n");
        return 0;
    } else {
        printf("[-] something went wrong...\n");
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    const auto ret = run_patcher(argc, argv);
    getchar();

    return ret;
}