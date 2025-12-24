#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>      // Low-level BPF wrappers
#include <bpf/libbpf.h>   // High-level BPF helpers

/* * Minimal BPF instructions for "return XDP_PASS"
 * essentially: mov r0, 2; exit;
 */
struct bpf_insn prog_insns[] = {
    { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .src_reg = 0, .off = 0, .imm = XDP_PASS },
    { .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }
};

/*
 * Loads the dummy XDP program into the kernel using modern libbpf API.
 * Returns the file descriptor (fd) of the loaded program.
 */
int load_dummy_prog() {
    char log_buf[65535];
    
    // Modern way to define load options
    struct bpf_prog_load_opts opts = {
        .sz = sizeof(struct bpf_prog_load_opts), // Version checking
        .log_buf = log_buf,
        .log_size = sizeof(log_buf),
        .log_level = 1,
    };

    // New API: bpf_prog_load(type, name, license, insns, insn_cnt, opts)
    int fd = bpf_prog_load(BPF_PROG_TYPE_XDP, 
                           "xdp_test_prog", 
                           "GPL", 
                           prog_insns, 
                           sizeof(prog_insns) / sizeof(struct bpf_insn), 
                           &opts);
    
    if (fd < 0) {
        fprintf(stderr, "Failed to load BPF program: %s\n", log_buf);
        return -1;
    }
    return fd;
}

/*
 * Probes the interface with a specific XDP flag.
 */
void probe_mode(int ifindex, int prog_fd, const char *mode_name, int flags) {
    printf("Testing %-10s... ", mode_name);
    fflush(stdout);

    // Try to attach
    int err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);

    if (err == 0) {
        printf("\033[0;32mSUPPORTED\033[0m\n"); // Green text
        // Detach immediately to clean up
        bpf_xdp_detach(ifindex, flags, NULL);
    } else if (err == -EOPNOTSUPP) {
        printf("\033[0;31mNOT SUPPORTED\033[0m (Driver/HW rejected)\n"); // Red text
    } else if (err == -EINVAL) {
        printf("\033[0;33mINVALID\033[0m (Interface might be down or parameters wrong)\n");
    } else if (err == -EBUSY) {
        printf("\033[0;33mBUSY\033[0m (Another XDP program is already loaded)\n");
    } else {
        printf("ERROR (Code: %d, %s)\n", err, strerror(-err));
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface_name>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("Invalid interface name");
        return 1;
    }

    printf("Probing XDP support for interface: %s (Index: %d)\n", ifname, ifindex);
    printf("----------------------------------------------------\n");

    int prog_fd = load_dummy_prog();
    if (prog_fd < 0) return 1;

    // 1. Test Native Mode (Driver)
    probe_mode(ifindex, prog_fd, "NATIVE", XDP_FLAGS_DRV_MODE);

    // 2. Test Offload Mode (Hardware)
    probe_mode(ifindex, prog_fd, "OFFLOAD", XDP_FLAGS_HW_MODE);

    // 3. Test Generic Mode (SKB)
    probe_mode(ifindex, prog_fd, "GENERIC", XDP_FLAGS_SKB_MODE);

    close(prog_fd);
    return 0;
}
