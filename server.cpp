#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <mutex>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>  // Changed from openssl/sha.h to modern OpenSSL
#include <vector>

const int PORT = 8080;
const int BUFFER_SIZE = 4096;
std::mutex cout_mutex;

// WebSocket protocol constants
const std::string WS_MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(const std::string &in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val>>valb)&0x3F]);
            valb -= 6;
        }
    }
    if (valb>-6) out.push_back(base64_chars[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
}

std::string calculate_accept_key(const std::string &client_key) {
    std::string combined = client_key + WS_MAGIC_KEY;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Modern OpenSSL 3.0 approach
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize SHA-1 digest");
    }

    if (EVP_DigestUpdate(mdctx, combined.c_str(), combined.length()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update digest");
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(mdctx);
    return base64_encode(std::string((char*)hash, hash_len));
}

void handle_websocket(int clientSocket) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    
    // Receive initial handshake
    int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived <= 0) {
        close(clientSocket);
        return;
    }

    std::string request(buffer, bytesReceived);
    
    // Check if this is a WebSocket handshake
    size_t key_pos = request.find("Sec-WebSocket-Key:");
    if (key_pos == std::string::npos) {
        close(clientSocket);
        return;
    }

    // Extract client key
    size_t key_end = request.find("\r\n", key_pos);
    std::string client_key = request.substr(key_pos + 19, key_end - (key_pos + 19));
    client_key.erase(0, client_key.find_first_not_of(" \t"));
    client_key.erase(client_key.find_last_not_of(" \t") + 1);

    // Calculate accept key
    std::string accept_key;
    try {
        accept_key = calculate_accept_key(client_key);
    } catch (const std::exception &e) {
        std::cerr << "Error calculating accept key: " << e.what() << std::endl;
        close(clientSocket);
        return;
    }

    // Send handshake response
    std::string response = 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept_key + "\r\n\r\n";
    
    send(clientSocket, response.c_str(), response.size(), 0);

    // Now in WebSocket mode
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytesReceived <= 0) break;

        // Decode WebSocket frame (simplified)
        if ((buffer[0] & 0x0F) == 0x01) { // Text frame
            int payload_len = buffer[1] & 0x7F;
            char mask[4];
            char *payload;
            
            if (payload_len <= 125) {
                memcpy(mask, &buffer[2], 4);
                payload = &buffer[6];
            } else {
                // Handle larger payloads
                close(clientSocket);
                return;
            }

            // Decode message
            std::string message;
            for (int i = 0; i < payload_len; i++) {
                message += (payload[i] ^ mask[i % 4]);
            }

            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Message received: " << message << std::endl;
            }

            // Prepare response (WebSocket format)
            std::string response_msg = message + " -Pong";
            char frame[BUFFER_SIZE];
            frame[0] = 0x81; // Text frame
            frame[1] = response_msg.size();
            memcpy(&frame[2], response_msg.c_str(), response_msg.size());
            
            send(clientSocket, frame, 2 + response_msg.size(), 0);
        }
    }
    
    close(clientSocket);
}

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error creating socket\n";
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        std::cerr << "Error setting SO_REUSEADDR\n";
    }

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr))) {
        std::cerr << "Error binding socket\n";
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == -1) {
        std::cerr << "Error listening on socket\n";
        close(serverSocket);
        return 1;
    }

    std::cout << "WebSocket server running on port " << PORT << std::endl;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        
        if (clientSocket == -1) {
            std::cerr << "Error accepting connection\n";
            continue;
        }

        std::thread(handle_websocket, clientSocket).detach();
    }

    close(serverSocket);
    return 0;
}
