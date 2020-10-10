#include <vector>
#include <fstream>
#include <filesystem>

#include "cxxopts.hpp"
#include "opendht.h"
#include "fmt/core.h"

namespace default_settings
{
    const std::string bootstrap_host = "bootstrap.jami.net";
    const std::string bootstrap_port = "4222";
    const std::string nodes_file = "nodes.bin";
    const std::string identity_name = "key";
};

const std::size_t export_nodes(const dht::DhtRunner& dht, const std::string& file_name)
{
    auto nodes = dht.exportNodes();

    if (nodes.size() == 0)
        return 0;

    std::ofstream nodes_file(file_name, std::ios::binary);
    msgpack::pack(nodes_file, nodes);

    return nodes.size();
}

const std::size_t import_nodes(dht::DhtRunner& dht, const std::string& file_name)
{
    if (!std::filesystem::exists(file_name))
        return 0;

    msgpack::unpacker pac;
    std::ifstream nodes_file(file_name, std::ios::binary | std::ios::ate);
    auto size = nodes_file.tellg();

    nodes_file.seekg(0, std::ios::beg);
    pac.reserve_buffer(size);
    nodes_file.read(pac.buffer(), size);
    pac.buffer_consumed(size);

    msgpack::object_handle oh;
    std::size_t node_count = 0;

    while (pac.next(oh)) {
        auto imported_nodes = oh.get().as<std::vector<dht::NodeExport>>();
        node_count += imported_nodes.size();

        dht.bootstrap(imported_nodes);
    }

    return node_count;
}

std::vector<uint8_t> read_file(const std::string& file_path)
{
    std::ifstream input_stream(file_path, std::ios::binary | std::ios::ate);
    auto end = input_stream.tellg();

    input_stream.seekg(0, std::ios::beg);

    auto size = end - input_stream.tellg();
    std::vector<uint8_t> buffer(size);

    input_stream.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    input_stream.close();

    return buffer;
}

std::shared_ptr<dht::crypto::Identity> load_identity(const std::string& identity_path, const std::string& password = {})
{
    auto private_key_path = fmt::format("{}.pem", identity_path);
    auto certificate_path = fmt::format("{}.crt", identity_path);

    if (!std::filesystem::exists(private_key_path))
        return nullptr;
    if (!std::filesystem::exists(certificate_path))
        return nullptr;
    
    auto private_key_buffer = read_file(private_key_path);
    auto certificate_buffer = read_file(certificate_path);

    if (private_key_buffer.empty())
        return nullptr; 
    if (certificate_buffer.empty())
        return nullptr;

    auto private_key = std::make_shared<dht::crypto::PrivateKey>(private_key_buffer, password);
    auto certificate = std::make_shared<dht::crypto::Certificate>(certificate_buffer);

    return std::make_shared<dht::crypto::Identity>(private_key, certificate);
}

int main(int argc, char** argv)
{
    dht::DhtRunner dht;
    dht::DhtRunner::Config config;
    std::shared_ptr<dht::crypto::Identity> identity;
    cxxopts::Options options("opendht-test", "A test program for the OpenDHT library");

    options.add_options()
        ("help", "Print usage")
        ("port", "Port for local DHT node", cxxopts::value<in_port_t>()->default_value("0"))
        ("bootstrap-host", "Bootstrap host", cxxopts::value<std::string>()->default_value(default_settings::bootstrap_host))
        ("bootstrap-port", "Bootstrap port", cxxopts::value<std::string>()->default_value(default_settings::bootstrap_port))
        ("nodes", "File name to export/load nodes", cxxopts::value<std::string>()->default_value(default_settings::nodes_file))
        ("identity", "File name to export/load identity", cxxopts::value<std::string>()->default_value(default_settings::identity_name))
        ("password", "Password for identity", cxxopts::value<std::string>()->default_value(""));

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        fmt::print("{}\n", options.help());
        exit(0);
    }

    auto identity_file = result["identity"].as<std::string>();
    auto password = result["password"].as<std::string>();

    try {
        identity = load_identity(identity_file, password);
        
        if (identity == nullptr) {
            identity = std::make_shared<dht::crypto::Identity>(dht::crypto::generateIdentity());

            dht::crypto::saveIdentity(*identity, identity_file, password);
        }
    } catch(const std::exception& exception) {
        fmt::print(stderr, "Failed to load identity: {}\n", exception.what());
        fmt::print(stderr, "Aborting...\n");
        exit(0);
    }

    auto public_key = identity->first->getPublicKey();

    fmt::print("Public Key Fingerprint: {}\n", public_key.getId().toString());

    config.threaded = true;
    config.dht_config.id = *identity;
    config.dht_config.node_config.network = 0;

    dht.run(result["port"].as<in_port_t>(), config);
    fmt::print("DHT is running on port {}...\n", dht.getBoundPort());

    auto nodes_file = result["nodes"].as<std::string>();
    auto import_count = import_nodes(dht, nodes_file);

    if (import_count == 0) {
        auto bootstrap_host = result["bootstrap-host"].as<std::string>();
        auto bootstrap_port = result["bootstrap-port"].as<std::string>();

        fmt::print("Bootstrapping with {}:{}...\n", bootstrap_host, bootstrap_port);
        dht.bootstrap(bootstrap_host, bootstrap_port);
    } else
        fmt::print("Imported {} node(s)!\n", import_count);

    while (dht.isRunning())
        if (getchar() == 'q') 
            break;

    auto export_count = export_nodes(dht, nodes_file);

    if (export_count > 0)
        fmt::print("Exported {} nodes!\n", export_count);

    fmt::print("Shutting down...\n");
    dht.shutdown();
    dht.join();

    return 0;
}