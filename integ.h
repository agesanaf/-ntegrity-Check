#pragma once
#include <windows.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>
#include <thread>
#include <chrono>
#include <memory>
#include <atomic>

namespace IntegrityCheck {
    std::atomic<bool> monitoring_active{ false };

    inline bool GetTextSegmentRange(uintptr_t& start, size_t& size) {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return false;
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
        auto section = IMAGE_FIRST_SECTION(ntHeaders);
        WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
        for (WORD i = 0; i < numberOfSections; i++, section++) {
            if (strncmp((char*)section->Name, ".text", 5) == 0) {
                start = (uintptr_t)hModule + section->VirtualAddress;
                size = section->Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    inline bool CalculateSHA256(const BYTE* data, size_t size, unsigned char* outHash) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_ptr(ctx, EVP_MD_CTX_free);
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) return false;
        if (EVP_DigestUpdate(ctx, data, size) != 1) return false;
        unsigned int hashLen = 0;
        if (EVP_DigestFinal_ex(ctx, outHash, &hashLen) != 1) return false;
        return hashLen == SHA256_DIGEST_LENGTH;
    }

    inline bool CompareHashes(const unsigned char* h1, const unsigned char* h2, size_t len) {
        return std::memcmp(h1, h2, len) == 0;
    }

    inline void PrintHash(const unsigned char* hash, size_t length) {
        for (size_t i = 0; i < length; i++)
            printf("%02x", hash[i]);
        printf("\n");
    }

    inline void RuntimeIntegrityMonitor() {
        uintptr_t textStart = 0;
        size_t textSize = 0;
        if (!GetTextSegmentRange(textStart, textSize)) {
            std::cerr << "Failed to find .text segment.\n";
            return;
        }

        BYTE* textSegment = (BYTE*)textStart;
        unsigned char originalHash[SHA256_DIGEST_LENGTH];
        bool firstRun = true;
        monitoring_active = true;

        std::cout << "Continuous hash monitoring started...\n";

        while (monitoring_active) {
            unsigned char currentHash[SHA256_DIGEST_LENGTH];

            if (CalculateSHA256(textSegment, textSize, currentHash)) {
                std::cout << "Hash: ";
                PrintHash(currentHash, SHA256_DIGEST_LENGTH);

                if (firstRun) {
                    memcpy(originalHash, currentHash, SHA256_DIGEST_LENGTH);
                    firstRun = false;
                }
                else {
                    if (!CompareHashes(originalHash, currentHash, SHA256_DIGEST_LENGTH)) {
                        std::cout << "\n*** PATCH DETECTED! TERMINATING! ***\n";
                        std::cout << "Original: ";
                        PrintHash(originalHash, SHA256_DIGEST_LENGTH);
                        std::cout << "Modified: ";
                        PrintHash(currentHash, SHA256_DIGEST_LENGTH);
                        exit(1);
                    }
                }
            }
            else {
                std::cout << "Failed to calculate hash\n";
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    inline void StartRuntimeMonitoring() {
        std::thread monitor_thread(RuntimeIntegrityMonitor);
        monitor_thread.detach();
    }

    inline void StopRuntimeMonitoring() {
        monitoring_active = false;
    }

    inline void RunForever() {
        StartRuntimeMonitoring();
        std::cout << "Integrity monitoring active. Program will run indefinitely...\n";
        std::cout << "Press Ctrl+C to terminate.\n\n";

        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}