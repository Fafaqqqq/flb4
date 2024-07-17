#include "Flb4.h"

#include <iostream>

#include <err.h>
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
    std::cout << "\n-----------------------\n" << std::endl;

    LOG << "Startig FLB4..." << END;


    __u32 flags = 0;

    auto bpf_obj = flb4_bpf::open_and_load();

    if (!bpf_obj)
        return -1;

    bpf_xdp_attach(1, -1, flags, nullptr);
    bpf_xdp_attach(2, -1, flags, nullptr);
    bpf_xdp_attach(1, bpf_program__fd(bpf_obj->progs.balancer_main), flags, nullptr);
    bpf_xdp_attach(2, bpf_program__fd(bpf_obj->progs.balancer_main), flags, nullptr);

    struct bpf_map *shared_map_ptr;
    shared_map_ptr = bpf_object__find_map_by_name(bpf_obj->obj, "example_map");

    int key = 0;
    int value = 32;
    bpf_map_update_elem(bpf_map__fd(shared_map_ptr), &key, &value, 0);
cleanup:
    flb4_bpf::destroy(bpf_obj);
 }