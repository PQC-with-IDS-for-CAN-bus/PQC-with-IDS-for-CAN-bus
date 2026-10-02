/**
 * ============================================================================
 * http_listener.hpp
 * ============================================================================
 *
 * Lightweight Embedded C++17 HTTP REST Server for Testbed Orchestration (:8080).
 * 
 * Standards & Specifications:
 *   - RFC 9112: HTTP/1.1 Specification (Message Syntax and Routing) [^1]
 *   - Orchestration Protocol: Capstone DockerLab Testbed Control Architecture [^2]
 *   - Endpoints Supported:
 *       GET  /health     -> Node readiness, busy flag, domain status, execution results
 *       POST /configure  -> Relay fault injection parameters (drops, bursts, flips)
 *       POST /prepare    -> ECU attestation preparation and domain key generation
 *       POST /run        -> Gateway scenario execution trigger and verification timeout
 * 
 * Design Invariants:
 *   - Zero external library dependencies (pure standard sockets and ISO C++17).
 *   - Runs asynchronously on dedicated background thread without blocking CAN event loops.
 *   - Returns strictly valid JSON responses matching controller.py schema expectations.
 *
 * Upstream Lineage:
 *   - Python Reference: Git repo/Phase 3/DockerLab/common.py (api(app) implementation)
 *   - Orchestration Controller: Git repo/Phase 3/DockerLab/controller.py
 *
 * Footnotes:
 *   [^1]: Fielding, R., et al. (2022). HTTP/1.1, RFC 9112, Internet Engineering Task Force.
 *   [^2]: Capstone Pure C++17 DockerLab Benchmarking Suite Charter, October 2026.
 * ============================================================================
 */

#ifndef HTTP_LISTENER_HPP
#define HTTP_LISTENER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <map>
#include <mutex>
#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
#define IS_VALID_SOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSE_SOCKET(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
using socket_t = int;
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#endif

namespace cisg::net {

/**
 * @brief HTTP Request Representation
 */
struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

/**
 * @brief HTTP Response Representation
 */
struct HttpResponse {
    int status_code{200};
    std::string status_text{"OK"};
    std::string content_type{"application/json"};
    std::string body{"{\"status\": \"ready\", \"ready\": true, \"busy\": false}"};
};

/**
 * @brief Handler Callback Function Type
 */
using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;

/**
 * @brief Embedded HTTP REST Server
 */
class HttpListener {
public:
    inline explicit HttpListener(uint16_t port = 8080)
        : port_(port)
#ifdef _WIN32
        , server_fd_(INVALID_SOCKET)
#else
        , server_fd_(-1)
#endif
    {
#ifdef _WIN32
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
    }

    inline ~HttpListener() {
        stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    HttpListener(const HttpListener&) = delete;
    HttpListener& operator=(const HttpListener&) = delete;

    inline void register_handler(const std::string& method, const std::string& path, HttpHandler handler) {
        std::lock_guard<std::mutex> lock(route_mutex_);
        routes_[method + " " + path] = handler;
    }

    inline bool start() {
        if (running_.load()) return true;

        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (!IS_VALID_SOCKET(server_fd_)) {
            std::cerr << "[!] HttpListener: failed to create socket\n";
            return false;
        }

        int opt = 1;
#ifdef _WIN32
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        struct sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port_);

        if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) < 0) {
            std::cerr << "[!] HttpListener: bind failed on port " << port_ << "\n";
            CLOSE_SOCKET(server_fd_);
            return false;
        }

        if (listen(server_fd_, 16) < 0) {
            std::cerr << "[!] HttpListener: listen failed on port " << port_ << "\n";
            CLOSE_SOCKET(server_fd_);
            return false;
        }

        running_.store(true);
        worker_thread_ = std::thread(&HttpListener::server_worker, this);
        std::cout << "[+] HttpListener listening on http://0.0.0.0:" << port_ << "\n";
        return true;
    }

    inline void stop() {
        if (!running_.exchange(false)) return;

        if (IS_VALID_SOCKET(server_fd_)) {
            CLOSE_SOCKET(server_fd_);
#ifdef _WIN32
            server_fd_ = INVALID_SOCKET;
#else
            server_fd_ = -1;
#endif
        }

        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    bool is_running() const noexcept { return running_.load(); }
    uint16_t port() const noexcept { return port_; }

private:
    inline void server_worker() {
        while (running_.load()) {
            struct sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            socket_t client_fd = accept(server_fd_, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);

            if (!IS_VALID_SOCKET(client_fd)) {
                if (!running_.load()) break;
                continue;
            }

            handle_client(client_fd);
            CLOSE_SOCKET(client_fd);
        }
    }

    inline void handle_client(socket_t client_fd) {
        char buffer[4096];
        int bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) return;

        buffer[bytes_read] = '\0';
        std::string raw_request(buffer, bytes_read);

        HttpRequest req = parse_request(raw_request);
        HttpResponse resp;

        std::string route_key = req.method + " " + req.path;
        HttpHandler handler;
        {
            std::lock_guard<std::mutex> lock(route_mutex_);
            auto it = routes_.find(route_key);
            if (it != routes_.end()) {
                handler = it->second;
            } else if (req.method == "GET" && req.path == "/") {
                auto it_health = routes_.find("GET /health");
                if (it_health != routes_.end()) handler = it_health->second;
            }
        }

        if (handler) {
            resp = handler(req);
        } else {
            resp.status_code = 404;
            resp.status_text = "Not Found";
            resp.body = "{\"status\": \"not_found\", \"error\": \"Unknown route\"}";
        }

        std::string raw_resp = serialize_response(resp);
        send(client_fd, raw_resp.c_str(), static_cast<int>(raw_resp.size()), 0);
    }

    static inline HttpRequest parse_request(const std::string& raw) {
        HttpRequest req;
        std::istringstream stream(raw);
        std::string line;

        if (std::getline(stream, line)) {
            std::istringstream line_stream(line);
            line_stream >> req.method >> req.path;
        }

        while (std::getline(stream, line) && line != "\r" && !line.empty()) {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = line.substr(0, colon);
                std::string val = line.substr(colon + 1);
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
                while (!val.empty() && (val.back() == '\r' || val.back() == ' ')) val.pop_back();
                req.headers[key] = val;
            }
        }

        // Remaining content is body
        std::stringstream body_stream;
        body_stream << stream.rdbuf();
        req.body = body_stream.str();
        return req;
    }

    static inline std::string serialize_response(const HttpResponse& resp) {
        std::ostringstream ss;
        ss << "HTTP/1.1 " << resp.status_code << " " << resp.status_text << "\r\n";
        ss << "Content-Type: " << resp.content_type << "\r\n";
        ss << "Content-Length: " << resp.body.size() << "\r\n";
        ss << "Access-Control-Allow-Origin: *\r\n";
        ss << "Connection: close\r\n\r\n";
        ss << resp.body;
        return ss.str();
    }

    uint16_t port_{8080};
    socket_t server_fd_;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    std::mutex route_mutex_;
    std::map<std::string, HttpHandler> routes_;
};

} // namespace cisg::net

#endif // HTTP_LISTENER_HPP
