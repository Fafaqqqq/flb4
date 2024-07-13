/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __FLB4_BPF_SKEL_H__
#define __FLB4_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct flb4_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *example_map;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *balancer_main;
	} progs;
	struct {
		struct bpf_link *balancer_main;
	} links;

#ifdef __cplusplus
	static inline struct flb4_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct flb4_bpf *open_and_load();
	static inline int load(struct flb4_bpf *skel);
	static inline int attach(struct flb4_bpf *skel);
	static inline void detach(struct flb4_bpf *skel);
	static inline void destroy(struct flb4_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
flb4_bpf__destroy(struct flb4_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
flb4_bpf__create_skeleton(struct flb4_bpf *obj);

static inline struct flb4_bpf *
flb4_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct flb4_bpf *obj;
	int err;

	obj = (struct flb4_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = flb4_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	flb4_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct flb4_bpf *
flb4_bpf__open(void)
{
	return flb4_bpf__open_opts(NULL);
}

static inline int
flb4_bpf__load(struct flb4_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct flb4_bpf *
flb4_bpf__open_and_load(void)
{
	struct flb4_bpf *obj;
	int err;

	obj = flb4_bpf__open();
	if (!obj)
		return NULL;
	err = flb4_bpf__load(obj);
	if (err) {
		flb4_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
flb4_bpf__attach(struct flb4_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
flb4_bpf__detach(struct flb4_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *flb4_bpf__elf_bytes(size_t *sz);

static inline int
flb4_bpf__create_skeleton(struct flb4_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "flb4_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "example_map";
	s->maps[0].map = &obj->maps.example_map;

	s->maps[1].name = "flb4_bpf.rodata";
	s->maps[1].map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "balancer_main";
	s->progs[0].prog = &obj->progs.balancer_main;
	s->progs[0].link = &obj->links.balancer_main;

	s->data = flb4_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *flb4_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x10\x15\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1c\0\
\x01\0\xbf\x16\0\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x63\x1a\xfc\xff\0\0\0\0\xbf\xa2\
\0\0\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x85\0\0\0\x01\0\0\0\x15\0\x06\0\0\0\0\0\x61\x04\0\0\0\0\0\0\x61\x63\x0c\0\0\0\
\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x17\0\0\0\x85\0\0\0\x06\0\
\0\0\xb7\0\0\0\x02\0\0\0\x95\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x69\x66\x69\x6e\x64\x65\x78\x3a\
\x20\x25\x64\x2c\x20\x76\x61\x6c\x75\x65\x3a\x20\x25\x64\0\x47\x50\x4c\0\x22\0\
\0\0\x05\0\x08\0\x02\0\0\0\x08\0\0\0\x14\0\0\0\x04\0\x08\x01\x51\x04\x08\x88\
\x01\x01\x56\0\x04\x40\x78\x01\x50\0\x01\x11\x01\x25\x25\x13\x05\x03\x25\x72\
\x17\x10\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\x8c\x01\x17\0\0\x02\x34\0\x03\x25\
\x49\x13\x3a\x0b\x3b\x0b\0\0\x03\x26\0\x49\x13\0\0\x04\x0f\0\x49\x13\0\0\x05\
\x15\x01\x49\x13\x27\x19\0\0\x06\x05\0\x49\x13\0\0\x07\x0f\0\0\0\x08\x26\0\0\0\
\x09\x2e\x01\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\x19\
\x49\x13\x3f\x19\0\0\x0a\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\x0b\
\x05\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x0c\x34\0\x02\x18\x03\x25\
\x3a\x0b\x3b\x0b\x49\x13\0\0\x0d\x34\0\x02\x22\x03\x25\x3a\x0b\x3b\x0b\x49\x13\
\0\0\x0e\x01\x01\x49\x13\0\0\x0f\x21\0\x49\x13\x37\x0b\0\0\x10\x24\0\x03\x25\
\x3e\x0b\x0b\x0b\0\0\x11\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x12\x18\0\0\0\x13\
\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\x0b\0\0\x14\x34\0\x03\x25\x49\x13\x3f\x19\
\x3a\x0b\x3b\x0b\x02\x18\0\0\x15\x13\x01\x0b\x0b\x3a\x0b\x3b\x0b\0\0\x16\x0d\0\
\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\x17\x04\x01\x49\x13\x03\x25\x0b\
\x0b\x3a\x0b\x3b\x05\0\0\x18\x28\0\x03\x25\x1c\x0f\0\0\x19\x13\x01\x03\x25\x0b\
\x0b\x3a\x0b\x3b\x05\0\0\x1a\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x05\x38\x0b\0\0\
\0\xcd\x01\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x1d\0\x01\x08\0\0\0\0\0\0\0\x02\x03\
\x88\0\0\0\x08\0\0\0\x0c\0\0\0\x02\x03\x2f\0\0\0\x01\x38\x03\x34\0\0\0\x04\x39\
\0\0\0\x05\x49\0\0\0\x06\x49\0\0\0\x06\x4a\0\0\0\0\x07\x04\x4f\0\0\0\x08\x09\
\x03\x88\0\0\0\x01\x5a\x19\x02\x63\x3e\x01\0\0\x0a\x04\x88\0\0\0\x02\x74\x02\
\xa1\0\x0b\0\x1a\x02\x63\x88\x01\0\0\x0c\x02\x91\x04\x0f\x02\x6e\x3e\x01\0\0\
\x0d\x01\x10\x02\x6f\x83\x01\0\0\0\x0e\x94\0\0\0\x0f\x9d\0\0\0\x17\0\x03\x99\0\
\0\0\x10\x05\x06\x01\x11\x06\x08\x07\x02\x07\xa9\0\0\0\x01\xb1\x03\xae\0\0\0\
\x04\xb3\0\0\0\x05\xc4\0\0\0\x06\xc8\0\0\0\x06\xcd\0\0\0\x12\0\x10\x08\x05\x08\
\x04\x94\0\0\0\x13\xd5\0\0\0\x0a\x03\x1b\x10\x09\x07\x04\x14\x0b\xe4\0\0\0\x02\
\x7a\x02\xa1\x01\x0e\x99\0\0\0\x0f\x9d\0\0\0\x04\0\x14\x0c\xfb\0\0\0\x04\x21\
\x02\xa1\x02\x15\x28\x04\x1b\x16\x0d\x2d\x01\0\0\x04\x1c\0\x16\x0f\x42\x01\0\0\
\x04\x1d\x08\x16\x10\x42\x01\0\0\x04\x1e\x10\x16\x11\x47\x01\0\0\x04\x1f\x18\
\x16\x12\x58\x01\0\0\x04\x20\x20\0\x04\x32\x01\0\0\x0e\x3e\x01\0\0\x0f\x9d\0\0\
\0\x02\0\x10\x0e\x05\x04\x04\xcd\0\0\0\x04\x4c\x01\0\0\x0e\x3e\x01\0\0\x0f\x9d\
\0\0\0\x0a\0\x04\x5d\x01\0\0\x0e\x3e\x01\0\0\x0f\x9d\0\0\0\0\0\x17\xd5\0\0\0\
\x18\x04\x05\xb0\x18\x18\x13\0\x18\x14\x01\x18\x15\x02\x18\x16\x03\x18\x17\x04\
\0\x04\x3e\x01\0\0\x04\x8d\x01\0\0\x19\x21\x18\x05\xbb\x18\x1a\x1b\xcd\0\0\0\
\x05\xbc\x18\0\x1a\x1c\xcd\0\0\0\x05\xbd\x18\x04\x1a\x1d\xcd\0\0\0\x05\xbe\x18\
\x08\x1a\x1e\xcd\0\0\0\x05\xc0\x18\x0c\x1a\x1f\xcd\0\0\0\x05\xc1\x18\x10\x1a\
\x20\xcd\0\0\0\x05\xc3\x18\x14\0\0\x8c\0\0\0\x05\0\0\0\0\0\0\0\x15\0\0\0\x47\0\
\0\0\x73\0\0\0\x87\0\0\0\x8f\0\0\0\x94\0\0\0\xa8\0\0\0\xb9\0\0\0\xbe\0\0\0\xcb\
\0\0\0\xd1\0\0\0\xdb\0\0\0\xe7\0\0\0\xec\0\0\0\xf0\0\0\0\xf4\0\0\0\xfa\0\0\0\
\x06\x01\0\0\x10\x01\0\0\x1c\x01\0\0\x25\x01\0\0\x2e\x01\0\0\x35\x01\0\0\x42\
\x01\0\0\x4d\x01\0\0\x5b\x01\0\0\x5f\x01\0\0\x64\x01\0\0\x6d\x01\0\0\x77\x01\0\
\0\x87\x01\0\0\x96\x01\0\0\xa5\x01\0\0\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\
\x69\x6f\x6e\x20\x31\x37\x2e\x30\x2e\x36\0\x2f\x68\x6f\x6d\x65\x2f\x79\x61\x73\
\x68\x2f\x72\x65\x70\x6f\x73\x2f\x70\x72\x6f\x6a\x65\x63\x74\x73\x2f\x66\x6c\
\x62\x34\x2f\x73\x72\x63\x2f\x62\x70\x66\x2f\x66\x6c\x62\x34\x2e\x62\x70\x66\
\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x79\x61\x73\x68\x2f\x72\x65\x70\x6f\x73\x2f\
\x70\x72\x6f\x6a\x65\x63\x74\x73\x2f\x66\x6c\x62\x34\x2f\x2e\x6f\x75\x74\x2f\
\x73\x72\x63\x2f\x62\x70\x66\0\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\
\x75\x70\x5f\x65\x6c\x65\x6d\0\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x63\x68\x61\x72\0\
\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\
\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\x6b\0\x6c\x6f\x6e\
\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\x33\x32\0\
\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x65\x78\x61\x6d\x70\x6c\x65\x5f\x6d\x61\
\x70\0\x74\x79\x70\x65\0\x69\x6e\x74\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x6d\
\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6d\x61\x70\x5f\x66\x6c\x61\x67\x73\
\0\x58\x44\x50\x5f\x41\x42\x4f\x52\x54\x45\x44\0\x58\x44\x50\x5f\x44\x52\x4f\
\x50\0\x58\x44\x50\x5f\x50\x41\x53\x53\0\x58\x44\x50\x5f\x54\x58\0\x58\x44\x50\
\x5f\x52\x45\x44\x49\x52\x45\x43\x54\0\x78\x64\x70\x5f\x61\x63\x74\x69\x6f\x6e\
\0\x62\x61\x6c\x61\x6e\x63\x65\x72\x5f\x6d\x61\x69\x6e\0\x63\x74\x78\0\x64\x61\
\x74\x61\0\x64\x61\x74\x61\x5f\x65\x6e\x64\0\x64\x61\x74\x61\x5f\x6d\x65\x74\
\x61\0\x69\x6e\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x72\x78\
\x5f\x71\x75\x65\x75\x65\x5f\x69\x6e\x64\x65\x78\0\x65\x67\x72\x65\x73\x73\x5f\
\x69\x66\x69\x6e\x64\x65\x78\0\x78\x64\x70\x5f\x6d\x64\0\x24\0\0\0\x05\0\x08\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\
\x01\0\x18\0\0\0\0\0\0\0\x40\x02\0\0\x40\x02\0\0\x10\x02\0\0\0\0\0\0\0\0\0\x02\
\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\
\x02\0\0\0\x04\0\0\0\x02\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\
\0\0\0\x02\x06\0\0\0\x19\0\0\0\0\0\0\x08\x07\0\0\0\x1f\0\0\0\0\0\0\x01\x04\0\0\
\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x09\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\
\x04\0\0\0\x0a\0\0\0\0\0\0\0\0\0\0\x02\x0b\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\
\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\x04\x28\0\0\0\x2c\0\0\0\x01\0\0\0\0\0\
\0\0\x31\0\0\0\x05\0\0\0\x40\0\0\0\x35\0\0\0\x05\0\0\0\x80\0\0\0\x3b\0\0\0\x08\
\0\0\0\xc0\0\0\0\x47\0\0\0\x0a\0\0\0\0\x01\0\0\x51\0\0\0\0\0\0\x0e\x0c\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\x02\x0f\0\0\0\x5d\0\0\0\x06\0\0\x04\x18\0\0\0\x64\0\0\
\0\x06\0\0\0\0\0\0\0\x69\0\0\0\x06\0\0\0\x20\0\0\0\x72\0\0\0\x06\0\0\0\x40\0\0\
\0\x7c\0\0\0\x06\0\0\0\x60\0\0\0\x8c\0\0\0\x06\0\0\0\x80\0\0\0\x9b\0\0\0\x06\0\
\0\0\xa0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xaa\0\0\0\x0e\0\0\0\xae\0\0\0\x01\
\0\0\x0c\x10\0\0\0\0\0\0\0\0\0\0\x0a\x13\0\0\0\xd5\x01\0\0\0\0\0\x01\x01\0\0\0\
\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x12\0\0\0\x04\0\0\0\x17\0\0\0\xda\x01\0\
\0\0\0\0\x0e\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x13\0\0\0\x04\0\0\0\
\x04\0\0\0\xf0\x01\0\0\0\0\0\x0e\x16\0\0\0\x01\0\0\0\xfa\x01\0\0\x01\0\0\x0f\0\
\0\0\0\x0d\0\0\0\0\0\0\0\x28\0\0\0\0\x02\0\0\x01\0\0\x0f\0\0\0\0\x15\0\0\0\0\0\
\0\0\x17\0\0\0\x08\x02\0\0\x01\0\0\x0f\0\0\0\0\x17\0\0\0\0\0\0\0\x04\0\0\0\0\
\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\
\x45\x5f\x5f\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x74\x79\x70\x65\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x6d\x61\x78\
\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6d\x61\x70\x5f\x66\x6c\x61\x67\x73\0\x65\
\x78\x61\x6d\x70\x6c\x65\x5f\x6d\x61\x70\0\x78\x64\x70\x5f\x6d\x64\0\x64\x61\
\x74\x61\0\x64\x61\x74\x61\x5f\x65\x6e\x64\0\x64\x61\x74\x61\x5f\x6d\x65\x74\
\x61\0\x69\x6e\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x72\x78\
\x5f\x71\x75\x65\x75\x65\x5f\x69\x6e\x64\x65\x78\0\x65\x67\x72\x65\x73\x73\x5f\
\x69\x66\x69\x6e\x64\x65\x78\0\x63\x74\x78\0\x62\x61\x6c\x61\x6e\x63\x65\x72\
\x5f\x6d\x61\x69\x6e\0\x78\x64\x70\0\x2f\x68\x6f\x6d\x65\x2f\x79\x61\x73\x68\
\x2f\x72\x65\x70\x6f\x73\x2f\x70\x72\x6f\x6a\x65\x63\x74\x73\x2f\x66\x6c\x62\
\x34\x2f\x73\x72\x63\x2f\x62\x70\x66\x2f\x66\x6c\x62\x34\x2e\x62\x70\x66\x2e\
\x63\0\x69\x6e\x74\x20\x62\x61\x6c\x61\x6e\x63\x65\x72\x5f\x6d\x61\x69\x6e\x28\
\x73\x74\x72\x75\x63\x74\x20\x78\x64\x70\x5f\x6d\x64\x2a\x20\x63\x74\x78\x29\
\x20\x7b\0\x20\x20\x20\x20\x69\x6e\x74\x20\x6b\x65\x79\x20\x3d\x20\x30\x3b\0\
\x20\x20\x20\x20\x76\x61\x6c\x75\x65\x20\x3d\x20\x28\x69\x6e\x74\x2a\x29\x62\
\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\
\x26\x65\x78\x61\x6d\x70\x6c\x65\x5f\x6d\x61\x70\x2c\x20\x26\x6b\x65\x79\x29\
\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x76\x61\x6c\x75\x65\x29\x20\x7b\0\x20\
\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\
\x69\x66\x69\x6e\x64\x65\x78\x3a\x20\x25\x64\x2c\x20\x76\x61\x6c\x75\x65\x3a\
\x20\x25\x64\x22\x2c\x20\x63\x74\x78\x2d\x3e\x69\x6e\x67\x72\x65\x73\x73\x5f\
\x69\x66\x69\x6e\x64\x65\x78\x2c\x20\x2a\x76\x61\x6c\x75\x65\x29\x3b\0\x09\x72\
\x65\x74\x75\x72\x6e\x20\x58\x44\x50\x5f\x50\x41\x53\x53\x3b\0\x63\x68\x61\x72\
\0\x62\x61\x6c\x61\x6e\x63\x65\x72\x5f\x6d\x61\x69\x6e\x2e\x5f\x5f\x5f\x5f\x66\
\x6d\x74\0\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x2e\x72\
\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\
\0\0\0\x14\0\0\0\x14\0\0\0\x7c\0\0\0\x90\0\0\0\0\0\0\0\x08\0\0\0\xbc\0\0\0\x01\
\0\0\0\0\0\0\0\x11\0\0\0\x10\0\0\0\xbc\0\0\0\x07\0\0\0\0\0\0\0\xc0\0\0\0\xf2\0\
\0\0\0\x8c\x01\0\x10\0\0\0\xc0\0\0\0\x1a\x01\0\0\x09\xb8\x01\0\x20\0\0\0\xc0\0\
\0\0\0\0\0\0\0\0\0\0\x28\0\0\0\xc0\0\0\0\x2b\x01\0\0\x13\xc4\x01\0\x40\0\0\0\
\xc0\0\0\0\x66\x01\0\0\x09\xcc\x01\0\x48\0\0\0\xc0\0\0\0\x77\x01\0\0\x09\xd0\
\x01\0\x78\0\0\0\xc0\0\0\0\xc3\x01\0\0\x02\xdc\x01\0\0\0\0\0\x0c\0\0\0\xff\xff\
\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\0\0\0\
\0\0\0\0\xe9\0\0\0\x05\0\x08\0\xb0\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\
\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\x05\0\0\0\0\x2c\0\0\0\x3d\0\0\0\x5c\0\0\0\
\x75\0\0\0\x03\x01\x1f\x02\x0f\x05\x1e\x06\x88\0\0\0\0\x95\x74\x70\x8f\xe4\x5e\
\x6e\x43\xa3\x3c\x2d\xae\x9e\x8c\x02\x90\xba\0\0\0\x01\x65\xe4\xdc\x8e\x31\x21\
\xf9\x1a\x5c\x2c\x9e\xb8\x56\x3c\x56\x92\xcc\0\0\0\x02\x95\x74\x70\x8f\xe4\x5e\
\x6e\x43\xa3\x3c\x2d\xae\x9e\x8c\x02\x90\xdf\0\0\0\x03\xb8\x10\xf2\x70\x73\x3e\
\x10\x63\x19\xb6\x7e\xf5\x12\xc6\x24\x6e\xea\0\0\0\x02\xd4\xde\x20\x2a\x60\x75\
\xea\x79\x52\xd5\xc3\x57\x8c\x35\xca\x19\xfe\0\0\0\x04\xb8\x3e\x7d\xe5\x0a\x4c\
\xc7\x6e\xf1\x2d\x07\x8a\x10\x87\xd3\x26\x04\x02\0\x09\x02\0\0\0\0\0\0\0\0\x03\
\xe2\0\x01\x05\x09\x0a\x03\x0b\x2e\x05\0\x06\x03\x92\x7f\x2e\x05\x13\x06\x03\
\xf1\0\x20\x05\x09\x3e\x21\x05\x02\x69\x02\x02\0\x01\x01\x2f\x68\x6f\x6d\x65\
\x2f\x79\x61\x73\x68\x2f\x72\x65\x70\x6f\x73\x2f\x70\x72\x6f\x6a\x65\x63\x74\
\x73\x2f\x66\x6c\x62\x34\x2f\x2e\x6f\x75\x74\x2f\x73\x72\x63\x2f\x62\x70\x66\0\
\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\0\x2f\x68\x6f\
\x6d\x65\x2f\x79\x61\x73\x68\x2f\x72\x65\x70\x6f\x73\x2f\x70\x72\x6f\x6a\x65\
\x63\x74\x73\x2f\x66\x6c\x62\x34\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\
\x65\x2f\x61\x73\x6d\x2d\x67\x65\x6e\x65\x72\x69\x63\0\x2f\x75\x73\x72\x2f\x69\
\x6e\x63\x6c\x75\x64\x65\x2f\x6c\x69\x6e\x75\x78\0\x2f\x68\x6f\x6d\x65\x2f\x79\
\x61\x73\x68\x2f\x72\x65\x70\x6f\x73\x2f\x70\x72\x6f\x6a\x65\x63\x74\x73\x2f\
\x66\x6c\x62\x34\x2f\x73\x72\x63\x2f\x62\x70\x66\x2f\x66\x6c\x62\x34\x2e\x62\
\x70\x66\x2e\x63\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\
\x2e\x68\0\x73\x72\x63\x2f\x62\x70\x66\x2f\x66\x6c\x62\x34\x2e\x62\x70\x66\x2e\
\x63\0\x69\x6e\x74\x2d\x6c\x6c\x36\x34\x2e\x68\0\x73\x72\x63\x2f\x62\x70\x66\
\x2f\x66\x6c\x62\x34\x5f\x6d\x61\x70\x73\x2e\x68\0\x62\x70\x66\x2e\x68\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfb\0\0\0\x04\0\xf1\
\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x27\x01\0\0\0\0\x03\0\x78\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\
\x01\0\x06\0\0\0\0\0\0\0\0\0\x17\0\0\0\0\0\0\0\0\0\0\0\x03\0\x06\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0c\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x03\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x15\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x03\0\x19\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb4\0\0\0\x12\0\x03\0\0\0\0\0\0\
\0\0\0\x88\0\0\0\0\0\0\0\x98\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x28\0\0\0\0\0\0\
\0\xd0\0\0\0\x11\0\x07\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\
\x01\0\0\0\x0f\0\0\0\x58\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x11\0\0\0\0\0\0\0\x03\0\0\0\x08\0\0\0\x15\0\0\0\0\0\0\0\
\x03\0\0\0\x0c\0\0\0\x1f\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x23\0\0\0\0\0\0\0\
\x03\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x0c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x1c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x24\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x2c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x34\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x3c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x44\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x48\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x4c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x50\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x54\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x58\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x5c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x64\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x6c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x70\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x74\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x78\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x7c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x80\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x84\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x88\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x8c\0\0\0\0\0\0\0\
\x03\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x05\0\0\0\x10\0\0\0\0\0\0\0\
\x02\0\0\0\x10\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x0f\0\0\0\x20\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x20\x02\0\0\0\0\0\0\x04\0\0\0\x0f\0\0\0\x38\x02\0\0\0\0\0\
\0\x03\0\0\0\x05\0\0\0\x50\x02\0\0\0\0\0\0\x04\0\0\0\x10\0\0\0\x2c\0\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x26\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x2a\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x2e\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x32\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x3e\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x53\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x7d\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\x92\0\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\xa7\0\0\0\0\0\0\0\
\x03\0\0\0\x0d\0\0\0\xc1\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x0e\x0f\x04\x10\0\
\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\
\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x62\x61\x6c\x61\x6e\x63\x65\
\x72\x5f\x6d\x61\x69\x6e\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x64\x65\x62\x75\
\x67\x5f\x6c\x6f\x63\x6c\x69\x73\x74\x73\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\
\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x6d\x61\x70\x73\0\
\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\
\x6e\x65\x5f\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\
\x64\x72\0\x2e\x72\x65\x6c\x78\x64\x70\0\x65\x78\x61\x6d\x70\x6c\x65\x5f\x6d\
\x61\x70\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x62\
\x61\x6c\x61\x6e\x63\x65\x72\x5f\x6d\x61\x69\x6e\0\x2e\x6c\x6c\x76\x6d\x5f\x61\
\x64\x64\x72\x73\x69\x67\0\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x72\x65\
\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\
\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x66\x6c\x62\x34\x2e\x62\x70\x66\x2e\x63\
\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\
\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x32\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x06\x01\0\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdc\x13\0\0\0\0\0\0\x2e\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x94\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x40\0\0\0\0\0\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x90\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x0f\0\0\
\0\0\0\0\x20\0\0\0\0\0\0\0\x1b\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x5f\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc8\0\0\0\0\0\0\0\
\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x16\x01\0\
\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\x17\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd2\0\0\0\x01\0\0\0\x03\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x0b\x01\0\0\0\0\0\0\x26\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x31\x01\0\0\0\0\0\0\x3c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xa8\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6d\x02\0\0\0\
\0\0\0\xd1\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xa4\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x0f\0\0\0\0\0\0\x50\
\0\0\0\0\0\0\0\x1b\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x4c\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3e\x04\0\0\0\0\0\0\x90\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\0\0\0\x09\0\0\0\x40\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x0f\0\0\0\0\0\0\x20\x02\0\0\0\0\0\0\x1b\0\0\
\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x65\0\0\0\x01\0\0\0\x30\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xce\x04\0\0\0\0\0\0\xac\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x84\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x7a\x06\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x80\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x08\x12\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x1b\0\0\0\x0f\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x22\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa4\
\x06\0\0\0\0\0\0\x68\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x1e\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x12\0\0\0\
\0\0\0\x30\0\0\0\0\0\0\0\x1b\0\0\0\x11\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0c\x0b\0\0\0\0\0\0\xb0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\
\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x12\0\0\0\0\0\0\x80\0\0\0\0\0\0\0\
\x1b\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xee\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\x0b\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xea\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xf8\x12\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1b\0\0\0\x15\0\0\0\x08\
\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xde\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xe8\x0b\0\0\0\0\0\0\xed\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xda\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x13\
\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\x1b\0\0\0\x17\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\
\0\0\0\0\x70\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd5\x0c\0\0\0\0\
\0\0\x04\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\xc2\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x13\0\0\0\0\0\
\0\x04\0\0\0\0\0\0\0\x1b\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0e\
\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\x0d\0\0\0\0\0\0\x98\x01\
\0\0\0\0\0\0\x01\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct flb4_bpf *flb4_bpf::open(const struct bpf_object_open_opts *opts) { return flb4_bpf__open_opts(opts); }
struct flb4_bpf *flb4_bpf::open_and_load() { return flb4_bpf__open_and_load(); }
int flb4_bpf::load(struct flb4_bpf *skel) { return flb4_bpf__load(skel); }
int flb4_bpf::attach(struct flb4_bpf *skel) { return flb4_bpf__attach(skel); }
void flb4_bpf::detach(struct flb4_bpf *skel) { flb4_bpf__detach(skel); }
void flb4_bpf::destroy(struct flb4_bpf *skel) { flb4_bpf__destroy(skel); }
const void *flb4_bpf::elf_bytes(size_t *sz) { return flb4_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
flb4_bpf__assert(struct flb4_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __FLB4_BPF_SKEL_H__ */
