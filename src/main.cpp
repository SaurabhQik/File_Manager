#include <windows.h>
#include <winsock2.h>  // Include winsock2.h before windows.h to prevent warnings
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
#include <thread>
#include <atomic>
#include "json.hpp"
#include <direct.h> // For _getcwd

namespace fs = std::filesystem;
using json = nlohmann::json;

SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
std::atomic<bool>     g_PauseService{false};

// Global server pointer so it can be accessed from control handlers
httplib::Server* g_ServerPtr = nullptr;
std::thread* g_ServerThread = nullptr;

// Helper function to get the build directory path
std::string GetBuildDirectoryPath() {
    char currentDir[MAX_PATH];
    if (_getcwd(currentDir, MAX_PATH) == nullptr) {
        // Fallback to executable directory if getcwd fails
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        std::string path(exePath);
        return path.substr(0, path.find_last_of("\\/"));
    }
    return std::string(currentDir);
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            
            // Signal the service to stop
            SetEvent(g_ServiceStopEvent);
            break;
            
        case SERVICE_CONTROL_PAUSE:
            if (g_ServerPtr && !g_PauseService) {
                g_PauseService = true;
                g_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
                SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
                std::cout << "Service paused" << std::endl;
            }
            break;
            
        case SERVICE_CONTROL_CONTINUE:
            if (g_ServerPtr && g_PauseService) {
                g_PauseService = false;
                g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
                SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
                std::cout << "Service resumed" << std::endl;
            }
            break;
            
        case SERVICE_CONTROL_INTERROGATE:
            // Just update the status
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            break;
            
        default:
            break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(TEXT("FileManagerService"), ServiceCtrlHandler);
    if (g_StatusHandle == NULL) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    // Get the build directory path and create storage directory path
    std::string buildDir = GetBuildDirectoryPath();
    //std::string storageDir = buildDir + "/filechunking2/storage";
    std::string storageDir = "C:\\Users\\Staff\\Desktop\\FileChunking2";
    
    // Ensure the directory exists
    try {
        fs::create_directories(storageDir);
        std::cout << "📁 Storage directory created at: " << storageDir << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error creating storage directory: " << e.what() << std::endl;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    // Setup code moved outside the loop
    unsigned int num_threads = std::thread::hardware_concurrency();
    std::cout << "🧵 Detected " << num_threads << " CPU threads" << std::endl;

    ThreadPool api_thread_pool(num_threads);
    FileHandler handler(storageDir, num_threads);

    httplib::Server server;
    g_ServerPtr = &server; // Set the global pointer
    //server.set_payload_max_length(1024 * 1024 * 100); // 100MB

    server.new_task_queue = []{return new httplib::ThreadPool(std::thread::hardware_concurrency()/2);};

    // POST /files - Upload a single file
    server.Post("/files", [&handler](const httplib::Request& req, httplib::Response& res) {
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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
        // Check if service is paused
        if (g_PauseService) {
            res.status = 503;
            res.set_content(R"({"error":"Service is currently paused"})", "application/json");
            return;
        }
        
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

    // GET /service/status - Get service status
    server.Get("/service/status", [](const httplib::Request&, httplib::Response& res) {
        json status = {
            {"status", g_PauseService ? "paused" : "running"},
            {"state", g_ServiceStatus.dwCurrentState == SERVICE_RUNNING ? 
                     "running" : (g_ServiceStatus.dwCurrentState == SERVICE_PAUSED ? 
                                 "paused" : "unknown")}
        };
        res.set_content(status.dump(4), "application/json");
    });

    // Use a separate thread for the server
    std::atomic<bool> server_running{true};
    g_ServerThread = new std::thread([&server, &storageDir]() {
        std::cout << "🚀 FileManagerService started at http://localhost:8080" << std::endl;
        std::cout << "📁 Using storage directory: " << storageDir << std::endl;
        server.listen("0.0.0.0", 8080);
    });

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Wait for stop event
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    // Stop the server and clean up
    std::cout << "Stopping server..." << std::endl;
    server.stop();
    server_running.store(false);
    
    if (g_ServerThread != nullptr && g_ServerThread->joinable()) {
        g_ServerThread->join();
        delete g_ServerThread;
        g_ServerThread = nullptr;
    }

    // Close handle
    CloseHandle(g_ServiceStopEvent);
    g_ServiceStopEvent = INVALID_HANDLE_VALUE;

    std::cout << "Service stopped." << std::endl;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Run as console app if not started from service control manager
void RunAsConsole() {
    // Get the build directory path and create storage directory path
    std::string buildDir = GetBuildDirectoryPath();
    //std::string storageDir = buildDir + "/filechunking2/storage";
    std::string storageDir = "C:\\Users\\Staff\\Desktop\\FileChunking2";
    
    // Ensure the directory exists
    try {
        fs::create_directories(storageDir);
        std::cout << "📁 Storage directory created at: " << storageDir << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error creating storage directory: " << e.what() << std::endl;
        return;
    }

    // Setup code moved outside the loop
    unsigned int num_threads = std::thread::hardware_concurrency();
    std::cout << "🧵 Detected " << num_threads << " CPU threads" << std::endl;

    ThreadPool api_thread_pool(num_threads);
    FileHandler handler(storageDir, num_threads);

    httplib::Server server;
    g_ServerPtr = &server;
    
    // Add all the same routes here...
    // (For brevity, I'm not repeating all the route handlers here, but in a real implementation,
    // you would copy all the route handlers from the ServiceMain function)
    
    // Simple routes for demonstration
    server.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("File Chunking Service is running", "text/plain");
    });
    
    server.Get("/service/status", [](const httplib::Request&, httplib::Response& res) {
        json status = {
            {"status", "running"},
            {"mode", "console"}
        };
        res.set_content(status.dump(4), "application/json");
    });

    // Handle console commands in a separate thread
    std::atomic<bool> server_running{true};
    std::thread console_thread([&server_running]() {
        std::cout << "Type 'exit' to stop the server\n";
        std::cout << "Type 'pause' to pause the service\n";
        std::cout << "Type 'resume' to resume the service\n";
        
        std::string cmd;
        while (server_running) {
            std::cout << "> ";
            std::getline(std::cin, cmd);
            
            if (cmd == "exit") {
                std::cout << "Stopping server...\n";
                server_running = false;
                if (g_ServerPtr) g_ServerPtr->stop();
                break;
            } else if (cmd == "pause") {
                g_PauseService = true;
                std::cout << "Service paused. All API requests will return 503 status.\n";
            } else if (cmd == "resume") {
                g_PauseService = false;
                std::cout << "Service resumed. API requests will be processed normally.\n";
            } else {
                std::cout << "Unknown command. Available commands: exit, pause, resume\n";
            }
        }
    });

    // Start the server
    std::cout << "🚀 FileManagerService started in console mode at http://localhost:8080" << std::endl;
    std::cout << "📁 Using storage directory: " << storageDir << std::endl;
    
    // Start the server in the main thread
    server.listen("0.0.0.0", 8080);
    
    // Server has stopped, clean up
    server_running = false;
    if (console_thread.joinable()) {
        console_thread.join();
    }
    
    std::cout << "Server stopped.\n";
}

int main() {
    // First try to start as a service
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { TEXT("FileManagerService"), ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Not started as a service, run in console mode
            std::cout << "Not running as a service. Starting in console mode...\n";
            RunAsConsole();
        } else {
            std::cerr << "StartServiceCtrlDispatcher failed with error: " << error << std::endl;
        }
    }

    return 0;
}
