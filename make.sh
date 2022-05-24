clang userspace.c -o userspace -W -Wall -O2 -lbpf

clang -O2 -g -Wall -target bpf -c ebpftest.c -o xdp_pass.o

ip link set eno1 xdpgeneric obj xdp_pass.o sec xdp_test
ip link set eno1 xdpgeneric off
