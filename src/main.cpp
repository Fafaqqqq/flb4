#include "Flb4.h"
#include "yaml-cpp/node/node.h"

#include <cstdint>
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

int main(int argc, char** argv) {

    YAML::Node config = YAML::LoadFile("flb4_config.yaml");

    if (!config["l4_tcp"]) {

        ERR << "Can not open config, doesn`t exist" << END;
        std::exit(-1);
    }

    LOG << "Successfuly load config" << END;
    LOG << "Startig FLB4..." << END;

    auto lsb_config = config["l4_tcp"]["fast"];

    auto     sub_addr_str = lsb_config["if_group"][1]["ip"].as<std::string>();
    uint32_t sub_addr = inet_addr(sub_addr_str.c_str());

    uint32_t rs_stat = 1;
    uint32_t flags   = 0;
    auto bpf_obj = flb4_bpf::open_and_load();

    if (!bpf_obj) {
        ERR << "Failed open/load bpf prog!" << END;
        return -1;
    }

    LOG << "Successfuly load bpf prog." << END;

    if (strcmp(argv[1], "attach") == 0) {
        for (uint32_t i = 0; i < lsb_config["if_group"].size(); i++) {
            int ifindex = lsb_config["if_group"][i]["index"].as<int>();

            bpf_xdp_attach(ifindex, -1, flags, nullptr);
            bpf_xdp_attach(ifindex, bpf_program__fd(bpf_obj->progs.balancer_main), flags, nullptr);
        }

        auto rs_map = bpf_object__find_map_by_name(bpf_obj->obj, "rs_map");
        auto rs_map_array =  bpf_object__find_map_by_name(bpf_obj->obj, "rs_map_array");

        auto addrs_start_str = lsb_config["rs"]["start"].as<std::string>();
        auto addrs_end_str   = lsb_config["rs"]["end"].as<std::string>();

        uint32_t addr_start = inet_addr(addrs_start_str.c_str());
        uint32_t addr_end = inet_addr(addrs_end_str.c_str());

        LOG << "start addr 0x" << std::hex << addr_start << END;
        LOG << "start end 0x" << std::hex << addr_end << END;

        uint32_t idx   = 1;
        uint32_t count = 1;
        for (uint32_t addr = ntohl(addr_start); addr < ntohl(addr_end); addr++) {
            auto rs_addr = htonl(addr);
            LOG << "pushing addr " << std::hex << rs_addr << " to rs_map" << END;
            bpf_map_update_elem(bpf_map__fd(rs_map), &rs_addr, &rs_stat, BPF_NOEXIST);
            bpf_map_update_elem(bpf_map__fd(rs_map_array), &idx, &rs_addr, BPF_ANY);
            idx++;
            count++;
        }

        idx = 0;
        bpf_map_update_elem(bpf_map__fd(rs_map_array), &idx, &count, BPF_ANY);

        auto sub_map =  bpf_object__find_map_by_name(bpf_obj->obj, "subnet_map");
        bpf_map_update_elem(bpf_map__fd(sub_map), &sub_addr, &rs_stat, BPF_NOEXIST);
        auto sub_map_array =  bpf_object__find_map_by_name(bpf_obj->obj, "subnet_map_array");

        idx = 0;
        count = 1;
        bpf_map_update_elem(bpf_map__fd(sub_map_array), &idx, &count, BPF_ANY);
        idx++;
        bpf_map_update_elem(bpf_map__fd(sub_map_array), &idx, &sub_addr, BPF_ANY);
    }

    if (strcmp(argv[1], "dettach") == 0) {
        for (uint32_t i = 0; i < lsb_config["if_group"].size(); i++) {
            int ifindex = lsb_config["if_group"][i]["index"].as<int>();

            bpf_xdp_attach(ifindex, -1, flags, nullptr);
        }
    }

cleanup:
    flb4_bpf::destroy(bpf_obj);
}