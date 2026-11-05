// Benign io_uring workload for the vol3-io-uring memory sample.
// Each mode leaves one ring alive and prints the ground truth as "TRUTH {json}" lines
// on stdout (the serial console), so the plugin tests can compare against it.
//   uring_demo listen   TCP listener on 127.0.0.1:4444 (plain syscalls, no io_uring)
//   uring_demo io       OPENAT+READ of a file, SOCKET+CONNECT+SEND to the listener
//   uring_demo sqpoll   ring with IORING_SETUP_SQPOLL, a few NOP/WRITE through the SQ thread
//   uring_demo reg      registered files and buffers, a personality, original fd closed
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define PORT 4444

struct ring {
    int fd;
    struct io_uring_params p;
    unsigned *sq_head, *sq_tail, *sq_mask, *sq_array, *sq_flags;
    unsigned *cq_head, *cq_tail, *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
};

static void die(const char *m) { perror(m); exit(1); }

static void ring_init(struct ring *r, unsigned entries, unsigned flags, unsigned idle) {
    memset(r, 0, sizeof(*r));
    r->p.flags = flags;
    r->p.sq_thread_idle = idle;
    r->fd = (int)syscall(__NR_io_uring_setup, entries, &r->p);
    if (r->fd < 0) die("io_uring_setup");
    size_t sz = r->p.sq_off.array + r->p.sq_entries * sizeof(unsigned);
    size_t csz = r->p.cq_off.cqes + r->p.cq_entries * sizeof(struct io_uring_cqe);
    if (csz > sz) sz = csz;  // IORING_FEAT_SINGLE_MMAP: one mapping for SQ and CQ rings
    char *m = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
    if (m == MAP_FAILED) die("mmap ring");
    r->sq_head = (unsigned *)(m + r->p.sq_off.head);
    r->sq_tail = (unsigned *)(m + r->p.sq_off.tail);
    r->sq_mask = (unsigned *)(m + r->p.sq_off.ring_mask);
    r->sq_array = (unsigned *)(m + r->p.sq_off.array);
    r->sq_flags = (unsigned *)(m + r->p.sq_off.flags);
    r->cq_head = (unsigned *)(m + r->p.cq_off.head);
    r->cq_tail = (unsigned *)(m + r->p.cq_off.tail);
    r->cq_mask = (unsigned *)(m + r->p.cq_off.ring_mask);
    r->cqes = (struct io_uring_cqe *)(m + r->p.cq_off.cqes);
    r->sqes = mmap(0, r->p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) die("mmap sqes");
    printf("TRUTH {\"kind\":\"ring\",\"pid\":%d,\"fd\":%d,\"flags\":%u,\"sq_entries\":%u,\"cq_entries\":%u}\n",
           getpid(), r->fd, r->p.flags, r->p.sq_entries, r->p.cq_entries);
}

static struct io_uring_sqe *sqe_get(struct ring *r, unsigned *slot) {
    unsigned tail = *r->sq_tail;
    *slot = tail & *r->sq_mask;
    struct io_uring_sqe *s = &r->sqes[*slot];
    memset(s, 0, sizeof(*s));
    return s;
}

// Publish one SQE, make the kernel consume it and wait for its CQE. Returns the CQE result.
// CQEs are not consumed here (cq head untouched) so the caller decides what stays pending.
static int submit_wait(struct ring *r, struct io_uring_sqe *s, unsigned slot) {
    unsigned tail = *r->sq_tail, before = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
    r->sq_array[slot] = slot;
    __atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
    if (r->p.flags & IORING_SETUP_SQPOLL) {
        if (__atomic_load_n(r->sq_flags, __ATOMIC_ACQUIRE) & IORING_SQ_NEED_WAKEUP)
            syscall(__NR_io_uring_enter, r->fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL, 0);
    } else if (syscall(__NR_io_uring_enter, r->fd, 1, 0, 0, NULL, 0) != 1) {
        die("io_uring_enter");
    }
    while (__atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE) == before) usleep(1000);
    struct io_uring_cqe *c = &r->cqes[before & *r->cq_mask];
    printf("TRUTH {\"kind\":\"sqe\",\"pid\":%d,\"fd\":%d,\"slot\":%u,\"opcode\":%u,\"flags\":%u,\"sqe_fd\":%d,"
           "\"len\":%u,\"user_data\":%llu,\"personality\":%u,\"buf_index\":%u}\n",
           getpid(), r->fd, slot, s->opcode, s->flags, s->fd, s->len, (unsigned long long)s->user_data,
           s->personality, s->buf_index);
    printf("TRUTH {\"kind\":\"cqe\",\"pid\":%d,\"fd\":%d,\"index\":%u,\"user_data\":%llu,\"res\":%d,\"flags\":%u}\n",
           getpid(), r->fd, before & *r->cq_mask, (unsigned long long)c->user_data, c->res, c->flags);
    return c->res;
}

static void ring_state(struct ring *r) {
    printf("TRUTH {\"kind\":\"state\",\"pid\":%d,\"fd\":%d,\"sq_head\":%u,\"sq_tail\":%u,\"cq_head\":%u,\"cq_tail\":%u}\n",
           getpid(), r->fd, *r->sq_head, *r->sq_tail, *r->cq_head, *r->cq_tail);
}

static void consume(struct ring *r, unsigned n) {
    __atomic_store_n(r->cq_head, *r->cq_head + n, __ATOMIC_RELEASE);
}

static struct sockaddr_in loopback(void) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

static void park(void) {
    fflush(stdout);
    for (;;) pause();
}

static int mode_listen(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a = loopback();
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(s, (void *)&a, sizeof(a)) || listen(s, 8)) die("listen");
    printf("TRUTH {\"kind\":\"listener\",\"pid\":%d,\"port\":%d}\n", getpid(), PORT);
    fflush(stdout);
    char buf[256];
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        if (fork() == 0) {  // keep each peer connected until the dump
            close(s);
            while (read(c, buf, sizeof(buf)) > 0) {}
            park();
        }
        close(c);
    }
}

static char path_io[] = "/data/report.txt";
static char msg[] = "hello from io_uring\n";

static int mode_io(void) {
    struct ring r;
    unsigned slot;
    static char buf[64];
    static struct sockaddr_in addr;
    addr = loopback();
    ring_init(&r, 8, 0, 0);

    struct io_uring_sqe *s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_OPENAT; s->fd = AT_FDCWD; s->addr = (uintptr_t)path_io;
    s->open_flags = O_RDONLY; s->user_data = 0x1001;
    int ffd = submit_wait(&r, s, slot);

    s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_READ; s->fd = ffd; s->addr = (uintptr_t)buf; s->len = sizeof(buf);
    s->user_data = 0x1002;
    submit_wait(&r, s, slot);

    s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_SOCKET; s->fd = AF_INET; s->off = SOCK_STREAM; s->user_data = 0x1003;
    int sfd = submit_wait(&r, s, slot);

    s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_CONNECT; s->fd = sfd; s->addr = (uintptr_t)&addr; s->off = sizeof(addr);
    s->user_data = 0x1004;
    submit_wait(&r, s, slot);

    s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_SEND; s->fd = sfd; s->addr = (uintptr_t)msg; s->len = strlen(msg);
    s->user_data = 0x1005;
    submit_wait(&r, s, slot);

    consume(&r, 3);  // OPENAT/READ/SOCKET seen by "the app", CONNECT/SEND left pending
    printf("TRUTH {\"kind\":\"files\",\"pid\":%d,\"opened_fd\":%d,\"path\":\"%s\",\"socket_fd\":%d}\n",
           getpid(), ffd, path_io, sfd);
    ring_state(&r);
    park();
    return 0;
}

static void sqpoll_tid(void) {
    DIR *d = opendir("/proc/self/task");
    struct dirent *e;
    char p[64], name[64];
    while (d && (e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof(p), "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        if (fgets(name, sizeof(name), f) && !strncmp(name, "iou-sqp-", 8)) {
            name[strcspn(name, "\n")] = 0;
            printf("TRUTH {\"kind\":\"sqpoll\",\"pid\":%d,\"tid\":%s,\"comm\":\"%s\"}\n", getpid(), e->d_name, name);
        }
        fclose(f);
    }
    if (d) closedir(d);
}

static int mode_sqpoll(void) {
    struct ring r;
    unsigned slot;
    static char line[] = "written by the SQPOLL thread\n";
    int lfd = open("/data/sqpoll.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (lfd < 0) die("open sqpoll.log");
    ring_init(&r, 4, IORING_SETUP_SQPOLL, 2000);

    struct io_uring_sqe *s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_NOP; s->user_data = 0x2001;
    submit_wait(&r, s, slot);

    s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_WRITE; s->fd = lfd; s->addr = (uintptr_t)line; s->len = strlen(line);
    s->user_data = 0x2002;
    submit_wait(&r, s, slot);

    s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_NOP; s->user_data = 0x2003;
    submit_wait(&r, s, slot);

    consume(&r, 3);
    printf("TRUTH {\"kind\":\"files\",\"pid\":%d,\"opened_fd\":%d,\"path\":\"/data/sqpoll.log\"}\n", getpid(), lfd);
    sqpoll_tid();
    ring_state(&r);
    park();
    return 0;
}

static int mode_reg(void) {
    struct ring r;
    unsigned slot;
    ring_init(&r, 8, 0, 0);

    int afd = open("/data/registered.txt", O_RDONLY);
    if (afd < 0) die("open registered.txt");
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = loopback();
    if (connect(sfd, (void *)&a, sizeof(a))) die("connect");
    int files[2] = {afd, sfd};
    if (syscall(__NR_io_uring_register, r.fd, IORING_REGISTER_FILES, files, 2)) die("register files");

    static char b0[4096] __attribute__((aligned(4096)));
    static char b1[8192] __attribute__((aligned(4096)));
    struct iovec iov[2] = {{b0, sizeof(b0)}, {b1, sizeof(b1)}};
    if (syscall(__NR_io_uring_register, r.fd, IORING_REGISTER_BUFFERS, iov, 2)) die("register buffers");

    int pers = (int)syscall(__NR_io_uring_register, r.fd, IORING_REGISTER_PERSONALITY, NULL, 0);
    if (pers < 0) die("register personality");

    printf("TRUTH {\"kind\":\"registered\",\"pid\":%d,\"fd\":%d,\"files\":[\"/data/registered.txt\",\"socket\"],"
           "\"file_fds\":[%d,%d],\"bufs\":[[%lu,%zu],[%lu,%zu]],\"personality\":%d,\"personality_uid\":%d}\n",
           getpid(), r.fd, afd, sfd, (unsigned long)b0, sizeof(b0), (unsigned long)b1, sizeof(b1), pers, getuid());
    close(afd);  // still reachable through the ring's fixed file table
    close(sfd);
    // Drop to uid/gid 1000: the personality keeps the root credentials it captured.
    if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) die("setresuid");

    struct io_uring_sqe *s = sqe_get(&r, &slot);
    s->opcode = IORING_OP_READ_FIXED; s->fd = 0; s->flags = IOSQE_FIXED_FILE;
    s->addr = (uintptr_t)b0; s->len = 64; s->buf_index = 0; s->personality = (unsigned short)pers;
    s->user_data = 0x3001;
    submit_wait(&r, s, slot);
    printf("TRUTH {\"kind\":\"closed\",\"pid\":%d,\"fds\":[%d,%d],\"uid_now\":%d}\n", getpid(), afd, sfd, getuid());
    ring_state(&r);
    park();
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "listen")) return mode_listen();
    if (!strcmp(argv[1], "io")) return mode_io();
    if (!strcmp(argv[1], "sqpoll")) return mode_sqpoll();
    if (!strcmp(argv[1], "reg")) return mode_reg();
    return 2;
}
