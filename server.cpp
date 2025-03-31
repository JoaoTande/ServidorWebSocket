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
#include <openssl/sha.h>
#include <vector>
#include <string>

const int PORT = 8080;
const int BUFFER_SIZE = 4096;
std::mutex cout_mutex;

// Constantes do protocolo WebSocket
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
    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)combined.c_str(), combined.length(), sha1);
    return base64_encode(std::string((char*)sha1, SHA_DIGEST_LENGTH));
}

void handle_websocket(int clientSocket) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    
    // Recebe handshake inicial
    int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived <= 0) {
        close(clientSocket);
        return;
    }

    std::string request(buffer, bytesReceived);
    
    // Verifica se é um handshake WebSocket
    size_t key_pos = request.find("Sec-WebSocket-Key:");
    if (key_pos == std::string::npos) {
        close(clientSocket);
        return;
    }

    // Extrai a chave do cliente
    size_t key_end = request.find("\r\n", key_pos);
    std::string client_key = request.substr(key_pos + 19, key_end - (key_pos + 19));
    client_key = client_key.substr(0, client_key.find_last_not_of(" \t") + 1);

    // Calcula a chave de resposta
    std::string accept_key = calculate_accept_key(client_key);

    // Envia resposta de handshake
    std::string response = 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept_key + "\r\n\r\n";
    
    send(clientSocket, response.c_str(), response.size(), 0);

    // Agora em modo WebSocket
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytesReceived <= 0) break;

        // Decodifica frame WebSocket (simplificado)
        // Nota: Implementação real precisa lidar com frames fragmentados, máscaras, etc.
        if ((buffer[0] & 0x0F) == 0x01) { // Frame de texto
            int payload_len = buffer[1] & 0x7F;
            char mask[4];
            char *payload;
            
            if (payload_len <= 125) {
                memcpy(mask, &buffer[2], 4);
                payload = &buffer[6];
            } else {
                // Lidar com payloads maiores
                close(clientSocket);
                return;
            }

            // Decodifica mensagem
            std::string message;
            for (int i = 0; i < payload_len; i++) {
                message += (payload[i] ^ mask[i % 4]);
            }

            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Mensagem recebida: " << message << std::endl;
            }

            // Prepara resposta (formato WebSocket)
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
        std::cerr << "Erro ao criar socket\n";
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Erro ao configurar SO_REUSEADDR\n";
    }

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr))) {
        std::cerr << "Erro ao fazer bind\n";
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == -1) {
        std::cerr << "Erro ao escutar\n";
        close(serverSocket);
        return 1;
    }

    std::cout << "Servidor WebSocket rodando na porta " << PORT << std::endl;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        
        if (clientSocket == -1) {
            std::cerr << "Erro ao aceitar conexão\n";
            continue;
        }

        std::thread(handle_websocket, clientSocket).detach();
    }

    close(serverSocket);
    return 0;
}
