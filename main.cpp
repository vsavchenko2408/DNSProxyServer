#include <iostream>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

struct Config {
    std::string upstream_dns_ip;
    std::unordered_set<std::string> blacklist;
    std::string blacklist_action;
    std::string redirect_ip;
};

bool load_config(const std::string &filename, Config &config) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open config file: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("upstream_dns_ip=") == 0) {
            config.upstream_dns_ip = line.substr(16);
        } else if (line.find("blacklist=") == 0) {
            config.blacklist.insert(line.substr(10));
        } else if (line.find("blacklist_action=") == 0) {
            config.blacklist_action = line.substr(17);
        } else if (line.find("redirect_ip=") == 0) {
            config.redirect_ip = line.substr(12);
        }
    }

    file.close();
    return true;
}

std::string extract_domain_from_dns_query(const char *buffer, size_t size) {
    std::string domain;
    size_t i = 12; // DNS header is 12 bytes
    while (i < size && buffer[i] != 0) {
        int length = buffer[i];
        domain += std::string(buffer + i + 1, length) + ".";
        i += length + 1;
    }
    if (!domain.empty()) {
        domain.pop_back(); // remove the trailing dot
    }
    return domain;
}

void handle_blacklisted_domain(const Config &config, char *buffer, size_t size, sockaddr_in &client_addr, int sockfd) {
    uint16_t flags = ntohs(*((uint16_t *)(buffer + 2)));
    flags |= (1 << 15); // Set response flag
    *((uint16_t *)(buffer + 2)) = htons(flags);

    if (config.blacklist_action == "NXDOMAIN") {
        *((uint16_t *)(buffer + 4)) = htons(3); // RCODE 3: NXDOMAIN
    } else if (config.blacklist_action == "REFUSED") {
        *((uint16_t *)(buffer + 4)) = htons(5); // RCODE 5: REFUSED
    } else if (config.blacklist_action == "REDIRECT" && !config.redirect_ip.empty()) {
        size_t answer_offset = size;
        buffer[answer_offset] = 0xc0; // Pointer to the domain name in the query section
        buffer[answer_offset + 1] = 0x0c;
        *((uint16_t *)(buffer + answer_offset + 2)) = htons(1); // Type A
        *((uint16_t *)(buffer + answer_offset + 4)) = htons(1); // Class IN
        *((uint32_t *)(buffer + answer_offset + 6)) = htonl(60); // TTL
        *((uint16_t *)(buffer + answer_offset + 10)) = htons(4); // RDLENGTH
        inet_pton(AF_INET, config.redirect_ip.c_str(), buffer + answer_offset + 12);

        *((uint16_t *)(buffer + 6)) = htons(1); // Answer RRs count
        size = answer_offset + 16;
    }

    sendto(sockfd, buffer, size, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
}

void forward_query_to_upstream(const Config &config, char *buffer, size_t size, sockaddr_in &client_addr, int sockfd) {
    sockaddr_in upstream_addr{};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);
    inet_pton(AF_INET, config.upstream_dns_ip.c_str(), &upstream_addr.sin_addr);

    int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    sendto(upstream_sock, buffer, size, 0, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));

    socklen_t addr_len = sizeof(upstream_addr);
    ssize_t len = recvfrom(upstream_sock, buffer, 512, 0, (struct sockaddr *)&upstream_addr, &addr_len);
    close(upstream_sock);

    if (len > 0) {
        sendto(sockfd, buffer, len, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
    }
}

int main() {
    Config config;
    if (!load_config("dns_proxy.conf", config)) {
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }

    char buffer[512];
    while (true) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &addr_len);

        if (len > 0) {
            std::string domain = extract_domain_from_dns_query(buffer, len);

            if (config.blacklist.find(domain) != config.blacklist.end()) {
                handle_blacklisted_domain(config, buffer, len, client_addr, sockfd);
            } else {
                forward_query_to_upstream(config, buffer, len, client_addr, sockfd);
            }
        }
    }

    close(sockfd);
    return 0;
}
