#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

struct Config {
    std::string upstream_dns;
    std::vector<std::string> blacklist;
    std::string response_type;
    std::string redirect_ip;
};

void trim_whitespace(std::string &str) {
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), str.end());
}

void parse_blacklist(const std::string &str, Config &config) {
    std::stringstream ss(str);
    std::string domain;

    while (std::getline(ss, domain, ',')) {
        trim_whitespace(domain);
        config.blacklist.push_back(domain);
    }
}

void read_config(const std::string &filename, Config &config) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening config file" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string line;
    while (std::getline(file, line)) {
        std::size_t equals_pos = line.find('=');
        if (equals_pos == std::string::npos) continue;

        std::string key = line.substr(0, equals_pos);
        std::string value = line.substr(equals_pos + 1);

        trim_whitespace(key);
        trim_whitespace(value);

        if (key == "upstream_dns") {
            config.upstream_dns = value;
        } else if (key == "blacklist") {
            parse_blacklist(value, config);
        } else if (key == "response_type") {
            config.response_type = value;
        } else if (key == "redirect_ip") {
            config.redirect_ip = value;
        }
    }
}

void print_config(const Config &config) {
    std::cout << "Upstream DNS: " << config.upstream_dns << std::endl;
    std::cout << "Response Type: " << config.response_type << std::endl;
    std::cout << "Redirect IP: " << config.redirect_ip << std::endl;

    std::cout << "Blacklist:" << std::endl;
    for (const auto &domain : config.blacklist) {
        std::cout << "  " << domain << std::endl;
    }
}

int main() {
    Config config;
    read_config("config.txt", config);
    print_config(config);

    return 0;
}
