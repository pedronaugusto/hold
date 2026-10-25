/* libarchive's side of hold's benchmark rows: the same trees (written by
 * `hold-bench --emit`), the same archives (bench/rivals.sh), the same
 * rows, each a whole archive read (every byte copied out) or written to
 * memory. Prints one line a row: "<row> <median ns per archive>".
 *   cc -O2 -I$(brew --prefix libarchive)/include bench/rivals/libarchive.c \
 *      -L$(brew --prefix libarchive)/lib -larchive -o libarchive-bench
 *   libarchive-bench <corpus dir> */
#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct tree {
    const char *name;
    int count;
    char **names;
    char **data;
    size_t *sizes;
    size_t total;
};

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(*len ? *len : 1);
    if (fread(b, 1, *len, f) != *len) { perror(path); exit(1); }
    fclose(f);
    return b;
}

/* The names in hold-bench's order. */
static void load(struct tree *t, const char *dir, const char *which) {
    t->name = which;
    int large = strcmp(which, "large") == 0;
    t->count = large ? 2 : 2000;
    t->names = calloc(t->count, sizeof(char *));
    t->data = calloc(t->count, sizeof(char *));
    t->sizes = calloc(t->count, sizeof(size_t));
    t->total = 0;
    for (int n = 0; n < t->count; n++) {
        char name[256], path[1024];
        if (large) snprintf(name, sizeof name, "%s", n == 0 ? "large/text.txt" : "large/random.bin");
        else snprintf(name, sizeof name, "src/d%d/f%d.txt", n % 40, n);
        snprintf(path, sizeof path, "%s/%s/%s", dir, which, name);
        t->names[n] = strdup(name);
        t->data[n] = slurp(path, &t->sizes[n]);
        t->total += t->sizes[n];
    }
}

static uint64_t now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static char scratch[64 * 1024];

static void read_archive(const char *bytes, size_t len, size_t want) {
    struct archive *a = archive_read_new();
    archive_read_support_format_all(a);
    if (archive_read_open_memory(a, bytes, len) != ARCHIVE_OK) { fprintf(stderr, "%s\n", archive_error_string(a)); exit(1); }
    struct archive_entry *e;
    size_t total = 0;
    while (archive_read_next_header(a, &e) == ARCHIVE_OK) {
        la_ssize_t n;
        while ((n = archive_read_data(a, scratch, sizeof scratch)) > 0) total += (size_t)n;
        if (n < 0) { fprintf(stderr, "%s\n", archive_error_string(a)); exit(1); }
    }
    archive_read_free(a);
    if (total != want) { fprintf(stderr, "read %zu of %zu\n", total, want); exit(1); }
}

enum kind { TAR, ZIP_DEFLATE, ZIP_STORE };

static char *out;
static size_t out_len;

static void write_archive(const struct tree *t, enum kind k) {
    struct archive *a = archive_write_new();
    if (k == TAR) archive_write_set_format_pax_restricted(a);
    else {
        archive_write_set_format_zip(a);
        archive_write_set_options(a, k == ZIP_DEFLATE ? "zip:compression=deflate,zip:compression-level=6" : "zip:compression=store");
    }
    archive_write_set_bytes_in_last_block(a, 1);
    size_t used = 0;
    if (archive_write_open_memory(a, out, out_len, &used) != ARCHIVE_OK) { fprintf(stderr, "%s\n", archive_error_string(a)); exit(1); }
    struct archive_entry *e = archive_entry_new();
    for (int n = 0; n < t->count; n++) {
        archive_entry_clear(e);
        archive_entry_set_pathname(e, t->names[n]);
        archive_entry_set_filetype(e, AE_IFREG);
        archive_entry_set_perm(e, 0644);
        archive_entry_set_size(e, (la_int64_t)t->sizes[n]);
        if (archive_write_header(a, e) != ARCHIVE_OK) { fprintf(stderr, "%s\n", archive_error_string(a)); exit(1); }
        if (archive_write_data(a, t->data[n], t->sizes[n]) < 0) { fprintf(stderr, "%s\n", archive_error_string(a)); exit(1); }
    }
    archive_entry_free(e);
    archive_write_close(a);
    archive_write_free(a);
}

static int compare(const void *x, const void *y) {
    double a = *(const double *)x, b = *(const double *)y;
    return a < b ? -1 : a > b;
}

/* Eleven samples of at least 10 ms each, after two warmups: the median
 * ns per archive. */
#define SAMPLES 11
static void row(const char *name, const struct tree *t, void (*fn)(const struct tree *, const char *, size_t, int), const char *bytes, size_t len, int arg) {
    double s[SAMPLES];
    for (int w = 0; w < 2; w++) fn(t, bytes, len, arg);
    for (int i = 0; i < SAMPLES; i++) {
        uint64_t start = now(), units = 0;
        do { fn(t, bytes, len, arg); units++; } while (now() - start < 10000000ull);
        s[i] = (double)(now() - start) / (double)units;
    }
    qsort(s, SAMPLES, sizeof s[0], compare);
    printf("%s/%s %.0f\n", name, t->name, s[SAMPLES / 2]);
    fflush(stdout);
}

static void do_read(const struct tree *t, const char *bytes, size_t len, int arg) { (void)arg; read_archive(bytes, len, t->total); }
static void do_write(const struct tree *t, const char *bytes, size_t len, int arg) { (void)bytes; (void)len; write_archive(t, (enum kind)arg); }

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "libarchive-bench <corpus dir>\n"); return 2; }
    const char *dir = argv[1];
    const char *which[] = {"tree", "large"};
    for (int w = 0; w < 2; w++) {
        struct tree t;
        load(&t, dir, which[w]);
        out_len = t.total + t.total / 4 + (1 << 20);
        out = malloc(out_len);
        char path[1024];
        size_t len;
        snprintf(path, sizeof path, "%s/%s.tar", dir, which[w]);
        char *tar = slurp(path, &len);
        row("tar/read", &t, do_read, tar, len, 0);
        row("tar/write", &t, do_write, NULL, 0, TAR);
        snprintf(path, sizeof path, "%s/%s-deflate.zip", dir, which[w]);
        size_t zlen;
        char *zip = slurp(path, &zlen);
        row("zip/read-deflate", &t, do_read, zip, zlen, 0);
        snprintf(path, sizeof path, "%s/%s-store.zip", dir, which[w]);
        size_t slen;
        char *store = slurp(path, &slen);
        row("zip/read-store", &t, do_read, store, slen, 0);
        row("zip/write-deflate", &t, do_write, NULL, 0, ZIP_DEFLATE);
        row("zip/write-store", &t, do_write, NULL, 0, ZIP_STORE);
        snprintf(path, sizeof path, "%s/%s-deflate.7z", dir, which[w]);
        size_t slen7;
        char *sz = slurp(path, &slen7);
        row("7z/read-deflate", &t, do_read, sz, slen7, 0);
    }
    return 0;
}
