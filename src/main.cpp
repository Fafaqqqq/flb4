#include "Flb4.h"
#include "yaml-cpp/node/node.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <err.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/bpf.h>
#include <linux/if_link.h>

#include <yaml-cpp/yaml.h>

#define LOG std::cout << "[LOG]: "
#define WAR std::cout << "[WAR]: "
#define ERR std::cerr << "[ERR]: "
#define END std::endl

namespace Lsb::Fast {

class BpfAdapter {
public:
    using RawBpf = flb4_bpf;

    enum Flags {
        ITEM_ANY     = BPF_ANY,   /* create new element or update existing */
        ITEM_NOEXIST = BPF_NOEXIST, /* create new element if it didn't exist */
        ITEM_EXIST   = BPF_EXIST, /* update existing element */
        ITEM_LOCK    = BPF_F_LOCK, /* spin_lock-ed map_lookup/map_update */
    };

    template<typename Key, typename Value>
    class Map {
    public:

    private:
        bpf_map*    map_;
        int         map_fd_;
        std::string name_;
    public:
        Map(RawBpf* info, const std::string& name)
        : map_fd_(0), name_(name) {
            map_     = bpf_object__find_map_by_name(info->obj, name.c_str());
            map_fd_  = bpf_map__fd(map_);
        }

        void init(RawBpf* info, const std::string& name) {
            map_    = bpf_object__find_map_by_name(info->obj, name.c_str());
            map_fd_ = bpf_map__fd(map_);
            name_   = name;
        }

        Value get(const Key& key) {
            Value val;
            if (0 != bpf_map_lookup_elem(map_fd_, &key, &val)) {
                throw std::runtime_error("map item not found");
            }

            return val;
        }
        void push(const Key& key, const Value& val, Flags flags) {
            if (0 != bpf_map_update_elem(map_fd_, &key, &val, flags)) {
                throw std::runtime_error("map item not found");
            }
        }
    };

private:
    RawBpf* bpf_ = nullptr;
    int     bpf_fd_   = 0;

public:
    BpfAdapter() {
        bpf_ = RawBpf::open_and_load();
        bpf_fd_ = bpf_program__fd(bpf_->progs.balancer_main);
    }

    ~BpfAdapter() {
        RawBpf::destroy(bpf_);
    }

    int attachTo(int ifindex, int flags) {
        dettachFrom(ifindex);
        return bpf_xdp_attach(ifindex, bpf_fd_, flags, nullptr);
        return 0;
    };

    int dettachFrom(int ifindex) {
        return bpf_xdp_attach(ifindex, -1, 0, nullptr);
        return 0;
    }

    RawBpf* getBpf() {
        return bpf_;
    }

}; // class BpfAdapter

class BpfLoader {
private:
    BpfAdapter adapter_;
    BpfAdapter::Map<uint32_t, uint32_t> rs_map_hash_;
    BpfAdapter::Map<uint32_t, uint32_t> rs_map_array_;
    BpfAdapter::Map<uint32_t, uint32_t> subnet_map_hash_;
    BpfAdapter::Map<uint32_t, uint32_t> subnet_map_array_;

public:
    BpfLoader()
    : rs_map_hash_(adapter_.getBpf(), "rs_map")
    , rs_map_array_(adapter_.getBpf(), "rs_map_array")
    , subnet_map_hash_(adapter_.getBpf(), "subnet_map")
    , subnet_map_array_(adapter_.getBpf(), "subnet_map_array") {}

    void loadConfig(const YAML::Node& config) {
        LOG << "LOADING CONFIG..." << END;
        LOG << "------------------------------" << END;
        auto nic_group    = config["nic_group"];
        auto subnet_group = config["subnet_group"];
        auto rs_groups    = config["real_servers_groups"];

        for (auto node : nic_group) {
            LOG << "Attaching xdp to " << node["id"].as<std::string>() << "/" << node["ip"].as<std::string>() << END;
            adapter_.attachTo(node["ifindex"].as<int>(), 0);
        }
        LOG << "Attached successfuly" << END;
        LOG << "------------------------------" << END;

        LOG << "Configuring real server maps" << END;
        configureRsGroup(rs_groups);
        LOG << "Configured successfuly" << END;
        LOG << "------------------------------" << END;

        LOG << "Configuring subnets maps" << END;
        configureSubnetGroup(subnet_group);
        LOG << "Configured successfuly" << END;
        LOG << "------------------------------" << END;
        LOG << "LOADING DONE" << END;
    }

    void unloadConfig(const YAML::Node& config) {
        LOG << "UNLOADING CONFIG..." << END;
        LOG << "------------------------------" << END;
        auto nic_group = config["nic_group"];

        for (auto node : nic_group) {
            LOG << "Dettaching xdp from " << node["id"].as<std::string>() << "/" << node["ip"].as<std::string>() << END;
            adapter_.dettachFrom(node["ifindex"].as<int>());
        }

    }

private:
    void configureRsGroup(const YAML::Node& group) {
        for (auto group : group) {
            uint32_t i = 0;
            if (group["type"].as<std::string>() == "list") {
                for (auto item : group["list"]) {
                    uint32_t rs_addr = inet_addr(item["addr"].as<std::string>().c_str());
                    rs_map_hash_.push(rs_addr, 1, BpfAdapter::ITEM_NOEXIST);
                    rs_map_array_.push(i + 1, rs_addr, BpfAdapter::ITEM_ANY);
                    i++;
                }
            }

            if (group["type"].as<std::string>() == "increasing_range") {
                uint32_t from_addr = inet_addr(group["from_addr"].as<std::string>().c_str());
                uint32_t to_addr   = inet_addr(group["to_addr"].as<std::string>().c_str());

                uint32_t i = 0;
                for (uint32_t addr = ntohl(from_addr); addr <= ntohl(to_addr); addr++) {
                    rs_map_hash_.push(htonl(addr), 1, BpfAdapter::ITEM_NOEXIST);
                    rs_map_array_.push(i + 1, htonl(addr), BpfAdapter::ITEM_ANY);
                    i++;
                }
            }

            rs_map_array_.push(0, i, BpfAdapter::ITEM_ANY);

        }
    }

    void configureSubnetGroup(const YAML::Node& group) {
        uint32_t i = 0;
        for (auto item : group) {
            uint32_t subnet_addr = inet_addr(item["addr"].as<std::string>().c_str());
            subnet_map_hash_.push(subnet_addr, 1, BpfAdapter::ITEM_NOEXIST);
            subnet_map_array_.push(i + 1, subnet_addr, BpfAdapter::ITEM_ANY);
            i++;
        }
        subnet_map_array_.push(0, i, BpfAdapter::ITEM_ANY);

    }
};  // class BpfLoader

} // namespace Lsb::Fast

YAML::Node loadYaml(const char* yaml_file) {
    YAML::Node config = YAML::LoadFile("flb4_config.yaml");

    if (!config["l4_tcp"]) {

        ERR << "Can not open config, doesn`t exist" << END;
        std::exit(-1);
    }

    LOG << "Successfuly load config" << END;
    LOG << "Startig LSB(Fast)..." << END;

    auto lsb_config = config["l4_tcp"]["fast"];

    return std::move(lsb_config);
}

int main(int argc, char** argv) {

    if (argc == 3) {
        if (strcmp(argv[1], "load") == 0) {

            auto config = loadYaml(argv[2]);
            Lsb::Fast::BpfLoader loader;
            loader.loadConfig(config);
        }

        if (strcmp(argv[1], "unload") == 0) {
            auto config = loadYaml(argv[2]);
            Lsb::Fast::BpfLoader loader;
            loader.unloadConfig(config);
        }
    }
    return 0;
}