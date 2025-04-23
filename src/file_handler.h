#pragma once
#include <string>
#include <fstream>
#include <filesystem>
#include <vector>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <future>
#include <thread>
#include <openssl/sha.h>
#include "json.hpp"
#include "thread_pool.h"
#include <queue>

namespace fs = std::filesystem;
using json = nlohmann::json;

class FileHandler {
private:
    std::string base_directory;
    std::string chunks_directory;
    std::string metadata_directory;
    const size_t CHUNK_SIZE = 1024 * 1024; // 1MB
    
    // ThreadPool for parallel processing
    ThreadPool thread_pool;
    
    // Mutex for protecting file operations
    mutable std::shared_mutex file_mutex;
    mutable std::shared_mutex chunk_mutex;
    mutable std::shared_mutex metadata_mutex;

    std::string sanitizeFilename(const std::string& filename) const {
        return std::regex_replace(filename, std::regex(R"([^\w\-.])"), "_");
    }

    std::string computeSHA256(const std::string& content) const {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(content.c_str()), content.size(), hash);
        
        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        
        return oss.str();
    }

    void storeChunkIfNew(const std::string& hash, const std::string& data) const {
        std::string chunkPath = chunks_directory + "/" + hash;
        
        // Use unique_lock for writing
        std::unique_lock<std::shared_mutex> lock(chunk_mutex);
        if (!fs::exists(chunkPath)) {
            std::ofstream chunkFile(chunkPath, std::ios::binary);
            if (!chunkFile) {
                throw std::runtime_error("Failed to create chunk file: " + chunkPath);
            }
            chunkFile.write(data.data(), data.size());
        }
    }

    bool increaseChunkRefCount(const std::string& hash) const {
        std::string refCountPath = chunks_directory + "/" + hash + ".refcount";
        int count = 1;
        
        std::unique_lock<std::shared_mutex> lock(chunk_mutex);
        
        if (fs::exists(refCountPath)) {
            std::ifstream refFile(refCountPath);
            refFile >> count;
            count++;
        }
        
        std::ofstream refFileWrite(refCountPath);
        refFileWrite << count;
        return true;
    }

    bool decreaseChunkRefCount(const std::string& hash) const {
        std::string refCountPath = chunks_directory + "/" + hash + ".refcount";
        
        std::unique_lock<std::shared_mutex> lock(chunk_mutex);
        
        if (!fs::exists(refCountPath)) return false;
        
        int count = 0;
        std::ifstream refFile(refCountPath);
        refFile >> count;
        refFile.close();
        
        count--;
        
        if (count <= 0) {
            // Delete the chunk and refcount file if no more references
            fs::remove(chunks_directory + "/" + hash);
            fs::remove(refCountPath);
            return true;
        }
        
        std::ofstream refFileWrite(refCountPath);
        refFileWrite << count;
        return true;
    }

    json createMetadata(const std::string& filename, const std::vector<std::string>& chunkHashes, size_t totalSize, const std::string& contentType) const {
        json meta;
        meta["filename"] = filename;
        meta["size"] = totalSize;
        meta["chunks"] = chunkHashes;
        meta["created_at"] = getCurrentISOTimeString();
        meta["modified_at"] = getCurrentISOTimeString();
        meta["content_type"] = contentType.empty() ? getContentType(filename) : contentType;
        
        return meta;
    }

    std::string getCurrentISOTimeString() const {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        
        std::tm tm_now;
        #ifdef _WIN32
            localtime_s(&tm_now, &time_t_now);
        #else
            localtime_r(&time_t_now, &tm_now);
        #endif
        
        std::ostringstream oss;
        oss << std::put_time(&tm_now, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    std::string getContentType(const std::string& filename) const {
        std::string ext = fs::path(filename).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        std::unordered_map<std::string, std::string> contentTypes = {
            {".pdf", "application/pdf"},
            {".txt", "text/plain"},
            {".html", "text/html"},
            {".htm", "text/html"},
            {".json", "application/json"},
            {".jpg", "image/jpeg"},
            {".jpeg", "image/jpeg"},
            {".png", "image/png"},
            {".gif", "image/gif"},
            {".csv", "text/csv"},
            {".doc", "application/msword"},
            {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            {".xls", "application/vnd.ms-excel"},
            {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
            {".ppt", "application/vnd.ms-powerpoint"},
            {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
            {".zip", "application/zip"},
            {".mp3", "audio/mpeg"},
            {".mp4", "video/mp4"},
            {".avi", "video/x-msvideo"},
            {".mov", "video/quicktime"}
        };
        
        auto it = contentTypes.find(ext);
        if (it != contentTypes.end()) {
            return it->second;
        }
        
        // Default content type if not found
        return "application/octet-stream";
    }
    
    // Process a single chunk in parallel
    std::future<std::string> processChunkAsync(const std::string& chunk) {
        return thread_pool.enqueue([this, chunk]() {
            std::string hash = computeSHA256(chunk);
            storeChunkIfNew(hash, chunk);
            increaseChunkRefCount(hash);
            return hash;
        });
    }

public:

    std::string getBaseDirectory() const {
        return base_directory;
    }
    FileHandler(const std::string& directory, size_t thread_count = std::thread::hardware_concurrency()) 
        : base_directory(directory), thread_pool(thread_count) {
        chunks_directory = base_directory + "/chunks";
        metadata_directory = base_directory + "/metadata";
        
        fs::create_directories(base_directory);
        fs::create_directories(chunks_directory);
        fs::create_directories(metadata_directory);
    }

    bool saveFile(const std::string& filename, const std::string& content, const std::string& contentType = "") {
        const size_t MAX_SIZE = 100 * 1024 * 1024; // 100MB limit
        if (content.size() > MAX_SIZE) return false;

        std::string safeName = sanitizeFilename(filename);
        std::vector<std::future<std::string>> futureHashes;
        
        // Process chunks in parallel
        for (size_t i = 0; i < content.size(); i += CHUNK_SIZE) {
            std::string chunk = content.substr(i, std::min(CHUNK_SIZE, content.size() - i));
            futureHashes.push_back(processChunkAsync(chunk));
        }
        
        // Collect results
        std::vector<std::string> chunkHashes;
        for (auto& future : futureHashes) {
            chunkHashes.push_back(future.get());
        }

        // Create and store metadata
        json meta = createMetadata(safeName, chunkHashes, content.size(), contentType);
        
        std::unique_lock<std::shared_mutex> lock(metadata_mutex);
        std::string metaPath = metadata_directory + "/" + safeName + ".json";
        std::ofstream metaFile(metaPath);
        if (!metaFile) {
            throw std::runtime_error("Failed to create metadata file: " + metaPath);
        }
        metaFile << meta.dump(4);
        
        return true;
    }

    std::string getFile(const std::string& filename) {
        std::string safeName = sanitizeFilename(filename);
        std::string metaPath = metadata_directory + "/" + safeName + ".json";
        
        // Use shared_lock for reading
        std::shared_lock<std::shared_mutex> metaLock(metadata_mutex);
        
        if (!fs::exists(metaPath)) return "";

        std::ifstream metaFile(metaPath);
        json meta;
        try {
            metaFile >> meta;
        } catch (const json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
            return "";
        }
        
        // Release metadata lock, we've read what we need
        metaLock.unlock();
        
        // Collect futures for parallel chunk reading
        std::vector<std::future<std::string>> futureChunks;
        
        // Fix: Properly handle JSON string values from array
        for (const auto& hashElement : meta["chunks"]) {
            // Make a copy of the string to ensure it doesn't get destroyed
            std::string hashCopy = hashElement.get<std::string>();
            
            futureChunks.push_back(thread_pool.enqueue([this](std::string hashCopy) {
                std::string chunkPath = chunks_directory + "/" + hashCopy;
                
                std::shared_lock<std::shared_mutex> chunkLock(chunk_mutex);
                if (!fs::exists(chunkPath)) {
                    return std::string();
                }
                
                std::ifstream chunk(chunkPath, std::ios::binary);
                if (!chunk) {
                    return std::string();
                }
                
                std::ostringstream oss;
                oss << chunk.rdbuf();
                return oss.str();
            },hashCopy));
        }

        // Collect and concatenate chunk data in correct order
        std::ostringstream finalContent;
        for (auto& future : futureChunks) {
            std::string chunkData = future.get();
            if (chunkData.empty()) {
                return ""; // Chunk read failed
            }
            finalContent << chunkData;
        }

        return finalContent.str();
    }

    json getMetadata(const std::string& filename) const {
        std::string safeName = sanitizeFilename(filename);
        std::string metaPath = metadata_directory + "/" + safeName + ".json";
        
        std::shared_lock<std::shared_mutex> lock(metadata_mutex);
        
        if (!fs::exists(metaPath)) {
            return json();
        }

        std::ifstream metaFile(metaPath);
        json meta;
        try {
            metaFile >> meta;
            return meta;
        } catch (const json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
            return json();
        }
    }

    std::string getChunk(const std::string& hash) const {
        std::shared_lock<std::shared_mutex> lock(chunk_mutex);
        
        std::string chunkPath = chunks_directory + "/" + hash;
        if (!fs::exists(chunkPath)) return "";
        
        std::ifstream chunk(chunkPath, std::ios::binary);
        std::ostringstream oss;
        oss << chunk.rdbuf();
        
        return oss.str();
    }

    bool updateFile(const std::string& filename, const std::string& content, const std::string& contentType = "") {
        if (!deleteFile(filename)) {
            return false;
        }
        
        return saveFile(filename, content, contentType);
    }

    bool updatePartial(const std::string& filename, const std::string& content, const std::string& contentType = "") {
        std::string safeName = sanitizeFilename(filename);
        std::string metaPath = metadata_directory + "/" + safeName + ".json";
        
        std::unique_lock<std::shared_mutex> lock(metadata_mutex);
        
        if (!fs::exists(metaPath)) {
            return false;
        }

        // Get original metadata
        std::ifstream metaFile(metaPath);
        json originalMeta;
        try {
            metaFile >> originalMeta;
        } catch (const json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
            return false;
        }
        metaFile.close();
        
        // Release metadata lock temporarily
        lock.unlock();
        
        // Process chunks in parallel
        std::vector<std::future<std::string>> futureHashes;
        for (size_t i = 0; i < content.size(); i += CHUNK_SIZE) {
            std::string chunk = content.substr(i, std::min(CHUNK_SIZE, content.size() - i));
            futureHashes.push_back(processChunkAsync(chunk));
        }
        
        // Collect results
        std::vector<std::string> newChunkHashes;
        for (auto& future : futureHashes) {
            newChunkHashes.push_back(future.get());
        }
        
        // Decrease reference counts for old chunks
        std::vector<std::future<void>> decreaseFutures;
        
        // Fix: Properly handle JSON string values from array
        for (const auto& hashElement : originalMeta["chunks"]) {
            // Make a copy of the string to ensure it doesn't get destroyed
            std::string hashCopy = hashElement.get<std::string>();
            
            decreaseFutures.push_back(thread_pool.enqueue([this, hashCopy]() {
                decreaseChunkRefCount(hashCopy);
            }));
        }
        
        // Wait for all decrease operations to complete
        for (auto& future : decreaseFutures) {
            future.wait();
        }
        
        // Create and store new metadata
        std::string metaContentType = contentType;
        if (contentType.empty() && !originalMeta.empty() && originalMeta.contains("content_type")) {
            metaContentType = originalMeta["content_type"].get<std::string>();
        }
        
        json newMeta = createMetadata(safeName, newChunkHashes, content.size(), metaContentType);
        newMeta["created_at"] = originalMeta.contains("created_at") ? 
            originalMeta["created_at"].get<std::string>() : getCurrentISOTimeString();
        
        // Reacquire metadata lock for writing
        lock.lock();
        std::ofstream newMetaFile(metaPath);
        newMetaFile << newMeta.dump(4);
        
        return true;
    }

    bool deleteFile(const std::string& filename) {
        std::string safeName = sanitizeFilename(filename);
        std::string metaPath = metadata_directory + "/" + safeName + ".json";
        
        std::unique_lock<std::shared_mutex> lock(metadata_mutex);
        
        if (!fs::exists(metaPath)) {
            return false;
        }

        // Load metadata to get chunk references
        std::ifstream metaFile(metaPath);
        json meta;
        try {
            metaFile >> meta;
        } catch (const json::parse_error& e) {
            std::cerr << "JSON parse error while deleting file: " << e.what() << std::endl;
            return false;
        }
        metaFile.close();
        
        // Delete metadata file
        fs::remove(metaPath);
        
        // Release metadata lock as we're done with it
        lock.unlock();
        
        // Decrease reference count for each chunk and potentially delete them (in parallel)
        std::vector<std::future<void>> futures;
        
        // Fix: Properly handle JSON string values from array
        for (const auto& hashElement : meta["chunks"]) {
            // Make a copy of the string to ensure it doesn't get destroyed
            std::string hashCopy = hashElement.get<std::string>();
            
            futures.push_back(thread_pool.enqueue([this, hashCopy]() {
                decreaseChunkRefCount(hashCopy);
            }));
        }
        
        // Wait for all tasks to complete
        for (auto& future : futures) {
            future.wait();
        }
        
        return true;
    }

    std::vector<std::string> listFiles() const {
        std::shared_lock<std::shared_mutex> lock(metadata_mutex);
        
        std::vector<std::string> files;
        for (const auto& entry : fs::directory_iterator(metadata_directory)) {
            if (entry.path().extension() == ".json") {
                files.push_back(entry.path().stem().string());
            }
        }
        return files;
    }
    
    // Method to save multiple files
    std::vector<std::pair<std::string, bool>> saveMultipleFiles(
        const std::vector<std::pair<std::string, std::string>>& nameContentPairs,
        const std::string& contentType = "") {
        
        std::vector<std::future<std::pair<std::string, bool>>> futures;
        
        // Process each file in parallel
        for (const auto& [filename, content] : nameContentPairs) {
            futures.push_back(thread_pool.enqueue([this, filename, content, contentType]() {
                bool success = saveFile(filename, content, contentType);
                return std::make_pair(filename, success);
            }));
        }
        
        // Collect results
        std::vector<std::pair<std::string, bool>> results;
        for (auto& future : futures) {
            results.push_back(future.get());
        }
        
        return results;
    }
};