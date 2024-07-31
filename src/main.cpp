#include "Flb4.h"

#include <cstdint>
#include <iostream>
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

    if (!config["flb4_tcp"]) {

        ERR << "Can not open config, doesn`t exist" << END;
        std::exit(-1);
    }

    LOG << "Successfuly load config" << END;
    LOG << "Startig FLB4..." << END;

    auto flb4_config = config["flb4_tcp"];

    auto      rs_addr_str = flb4_config["rs"]["addr"].as<std::string>();
    auto     sub_addr_str = flb4_config["if_group"][1]["ip"].as<std::string>();
    uint32_t  rs_addr = inet_addr(rs_addr_str.c_str());
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
        for (uint32_t i = 0; i < flb4_config["if_group"].size(); i++) {
            int ifindex = flb4_config["if_group"][i]["index"].as<int>();

            bpf_xdp_attach(ifindex, -1, flags, nullptr);
            bpf_xdp_attach(ifindex, bpf_program__fd(bpf_obj->progs.balancer_main), flags, nullptr);
        }

        auto rs_map = bpf_object__find_map_by_name(bpf_obj->obj, "rs_map");
        auto sub_map =  bpf_object__find_map_by_name(bpf_obj->obj, "subnet_map");
        bpf_map_update_elem(bpf_map__fd(rs_map), &rs_addr, &rs_stat, BPF_NOEXIST);
        bpf_map_update_elem(bpf_map__fd(sub_map), &sub_addr, &rs_stat, BPF_NOEXIST);

        auto  rs_map_array =  bpf_object__find_map_by_name(bpf_obj->obj, "rs_map_array");
        auto sub_map_array =  bpf_object__find_map_by_name(bpf_obj->obj, "subnet_map_array");

        uint32_t idx = 0;
        uint32_t val = 1;
        bpf_map_update_elem(bpf_map__fd(rs_map_array), &idx, &val, BPF_ANY);
        idx++;
        bpf_map_update_elem(bpf_map__fd(rs_map_array), &idx, &rs_addr, BPF_ANY);

        idx = 0;
        val = 1;
        bpf_map_update_elem(bpf_map__fd(sub_map_array), &idx, &val, BPF_ANY);
        idx++;
        bpf_map_update_elem(bpf_map__fd(sub_map_array), &idx, &sub_addr, BPF_ANY);
    }

    if (strcmp(argv[1], "dettach") == 0) {
        for (uint32_t i = 0; i < flb4_config["if_group"].size(); i++) {
            int ifindex = flb4_config["if_group"][i]["index"].as<int>();

            bpf_xdp_attach(ifindex, -1, flags, nullptr);
        }
    }

cleanup:
    flb4_bpf::destroy(bpf_obj);
}