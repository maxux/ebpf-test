#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

struct counters {
    __u64 rx_packets;
    __u64 rx_bytes;
};

void dies(char *str) {
    fprintf(stderr, "[-] %s", str);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    struct counters value;
    char *filename = "./xdp_pass.o";
    int fd;

    if(argc > 1)
        filename = argv[1];

    /*
    struct bpf_object *obj = bpf_object__open(filename);
    if(libbpf_get_error(obj))
        dies("could not open bpf object");

    bpf_object__load(obj);
    if(libbpf_get_error(obj))
        dies("could not load bpf object");

    if((fd = bpf_object__find_map_fd_by_name(obj, "xdp_stats_map")) < 0)
        dies("could not find map in the object");
    */

    fd = bpf_obj_get(filename);
	if (fd < 0) {
		fprintf(stderr,
			"WARN: Failed to open bpf map file:%s err(%d):%s\n",
			filename, errno, strerror(errno));
		return fd;
	}

    for(__u32 key = 0; key < 16; key++) {
        if((bpf_map_lookup_elem(fd, &key, &value)) != 0)
            dies("could not key in map");

        printf("ID % 3d: %llu, %llu\n", key, value.rx_packets, value.rx_bytes);
    }

    return 0;
}
