#include "../include/httplib.h"
#include "file_handler.h"
#include "thread_pool.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <future>
#include <chrono>
#include "json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

int main() {
    unsigned int num_threads = std::thread::hardware_concurrency();
    std::cout << "🧵 Detected " << num_threads << " CPU threads" << std::endl;

    ThreadPool api_thread_pool(num_threads);
    FileHandler handler("./storage", num_threads);

    httplib::Server server;
    server.set_payload_max_length(1024 * 1024 * 100); // 100MB

    server.new_task_queue = []{return new httplib::ThreadPool(std::thread::hardware_concurrency()/2);};

    // POST /files - Upload a single file
    server.Post("/files", [&handler](const httplib::Request& req, httplib::Response& res) {
        auto start = std::chrono::high_resolution_clock::now();

        if (!req.has_file("file")) {
            res.status = 400;
            res.set_content(R"({"error":"No file uploaded"})", "application/json");
            return;
        }

        const auto& file = req.get_file_value("file");
        std::string contentType = req.has_param("content_type") ? req.get_param_value("content_type") : "";

        try {
            bool success = handler.saveFile(file.filename, file.content, contentType);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start
            ).count();

            if (success) {
                json response = {
                    {"success", true},
                    {"message", "File uploaded successfully"},
                    {"filename", file.filename},
                    {"processing_time_ms", duration}
                };
                res.set_content(response.dump(), "application/json");
            } else {
                res.status = 400;
                res.set_content(R"({"error":"File upload failed or file too large"})", "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // POST /files/multi - Upload multiple files
    server.Post("/files/multi", [&handler](const httplib::Request& req, httplib::Response& res) {
        auto start = std::chrono::high_resolution_clock::now();

        if (req.files.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"No files uploaded"})", "application/json");
            return;
        }

        std::string defaultContentType = req.has_param("content_type") ? req.get_param_value("content_type") : "";
        std::vector<std::pair<std::string, std::string>> files;

        for (const auto& [key, file] : req.files) {
            if (key.rfind("file", 0) == 0) {
                std::string ctKey = key + "_content_type";
                std::string fileCT = req.has_param(ctKey) ? req.get_param_value(ctKey) : defaultContentType;
                files.emplace_back(file.filename, file.content);
            }
        }

        try {
            auto results = handler.saveMultipleFiles(files, defaultContentType);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start
            ).count();

            json successFiles = json::array();
            json failedFiles = json::array();

            for (const auto& [filename, ok] : results) {
                (ok ? successFiles : failedFiles).push_back(filename);
            }

            res.set_content(json{
                {"success", !successFiles.empty()},
                {"message", "Files processed"},
                {"successful_files", successFiles},
                {"failed_files", failedFiles},
                {"total_successful", successFiles.size()},
                {"total_failed", failedFiles.size()},
                {"processing_time_ms", duration}
            }.dump(), "application/json");

        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // GET /files/{filename}
    server.Get(R"(/files/([^/]+))", [&handler](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.matches[1];

        try {
            auto start = std::chrono::high_resolution_clock::now();
            std::string content = handler.getFile(filename);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start
            ).count();

            if (content.empty()) {
                res.status = 404;
                res.set_content(R"({"error":"File not found"})", "application/json");
                return;
            }

            json metadata = handler.getMetadata(filename);
            std::string contentType = metadata.contains("content_type") ? metadata["content_type"] : "application/octet-stream";

            res.set_content(content, contentType);
            res.set_header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
            res.set_header("X-Processing-Time", std::to_string(duration) + "ms");

        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // GET /chunks/{hash}
    server.Get(R"(/chunks/([^/]+))", [&handler](const httplib::Request& req, httplib::Response& res) {
        std::string hash = req.matches[1];

        try {
            std::string chunk = handler.getChunk(hash);
            if (chunk.empty()) {
                res.status = 404;
                res.set_content(R"({"error":"Chunk not found"})", "application/json");
                return;
            }
            res.set_content(chunk, "application/octet-stream");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // PUT /files/{filename}
    server.Put(R"(/files/([^/]+))", [&handler](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.matches[1];

        if (!req.has_file("file")) {
            res.status = 400;
            res.set_content(R"({"error":"No file uploaded for update"})", "application/json");
            return;
        }

        const auto& file = req.get_file_value("file");
        std::string contentType = req.has_param("content_type") ? req.get_param_value("content_type") : "";

        try {
            auto start = std::chrono::high_resolution_clock::now();
            bool updated = handler.updatePartial(filename, file.content, contentType);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start
            ).count();

            if (updated) {
                res.set_content(json{
                    {"success", true},
                    {"message", "File updated successfully"},
                    {"filename", filename},
                    {"processing_time_ms", duration}
                }.dump(), "application/json");
            } else {
                res.status = 404;
                res.set_content(R"({"error":"File not found or update failed"})", "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // DELETE /files/{filename}
    server.Delete(R"(/files/([^/]+))", [&handler](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.matches[1];

        try {
            auto start = std::chrono::high_resolution_clock::now();
            bool deleted = handler.deleteFile(filename);
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start
            ).count();

            if (deleted) {
                res.set_content(json{
                    {"success", true},
                    {"message", "File deleted successfully"},
                    {"filename", filename},
                    {"processing_time_ms", duration}
                }.dump(), "application/json");
            } else {
                res.status = 404;
                res.set_content(R"({"error":"File not found"})", "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // GET /files/{filename}/metadata
    server.Get(R"(/files/([^/]+)/metadata)", [&handler](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.matches[1];

        try {
            json metadata = handler.getMetadata(filename);
            if (!metadata.empty()) {
                res.set_content(metadata.dump(4), "application/json");
            } else {
                res.status = 404;
                res.set_content(R"({"error":"File metadata not found"})", "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // GET /files - List files
    server.Get("/files", [&handler](const httplib::Request&, httplib::Response& res) {
        try {
            auto files = handler.listFiles();
            res.set_content(json{
                {"files", files},
                {"count", files.size()}
            }.dump(4), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // DELETE /files - Bulk delete
    server.Delete("/files", [&handler, &api_thread_pool](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("files")) {
            res.status = 400;
            res.set_content(R"({"error":"No files parameter provided"})", "application/json");
            return;
        }

        try {
            auto filesJson = json::parse(req.get_param_value("files"));
            if (!filesJson.is_array()) {
                res.status = 400;
                res.set_content(R"({"error":"Files must be a JSON array"})", "application/json");
                return;
            }

            auto start = std::chrono::high_resolution_clock::now();
            std::vector<std::future<std::pair<std::string, bool>>> tasks;

            for (const auto& f : filesJson) {
                tasks.push_back(api_thread_pool.enqueue([&handler, f]() {
                    return std::make_pair(f.get<std::string>(), handler.deleteFile(f.get<std::string>()));
                }));
            }

            json successFiles = json::array();
            json failedFiles = json::array();

            for (auto& t : tasks) {
                auto [name, ok] = t.get();
                (ok ? successFiles : failedFiles).push_back(name);
            }

            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start
            ).count();

            res.set_content(json{
                {"success", !successFiles.empty()},
                {"successful_deletions", successFiles},
                {"failed_deletions", failedFiles},
                {"total_successful", successFiles.size()},
                {"total_failed", failedFiles.size()},
                {"processing_time_ms", duration}
            }.dump(4), "application/json");

        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // GET /stats - Disk stats
    server.Get("/stats", [&handler](const httplib::Request&, httplib::Response& res) {
        try {
            fs::space_info info = fs::space(handler.getBaseDirectory());
            json stats = {
                {"total_mb", info.capacity / (1024 * 1024)},
                {"free_mb", info.free / (1024 * 1024)},
                {"used_mb", (info.capacity - info.free) / (1024 * 1024)}
            };
            res.set_content(stats.dump(4), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    std::cout << "🚀 FileManagerService started at http://localhost:8080" << std::endl;
    server.listen("0.0.0.0", 8080);
    return 0;
}
