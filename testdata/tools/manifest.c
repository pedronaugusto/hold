/* The manifest of an archive as libarchive reads it: one line per entry,
 * "<kind> <size> <mode> <mtime> <fnv1a64 of contents> <name>\t<link>".
 * hold's interop tests compute the same lines and compare. Built by hand:
 *   cc -O2 -I$(brew --prefix libarchive)/include testdata/tools/manifest.c \
 *      -L$(brew --prefix libarchive)/lib -larchive -o manifest */
#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
#include <stdio.h>

static const char *kind(struct archive_entry *e) {
    if (archive_entry_hardlink(e)) return "hardlink";
    switch (archive_entry_filetype(e)) {
    case AE_IFREG: return "file";
    case AE_IFDIR: return "directory";
    case AE_IFLNK: return "symlink";
    case AE_IFCHR: return "character_device";
    case AE_IFBLK: return "block_device";
    case AE_IFIFO: return "fifo";
    default: return "other";
    }
}

int main(int argc, char **argv) {
    struct archive *a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    /* AppleDouble `._` entries stay entries, as every reader but
     * libarchive's macOS build reads them. */
    archive_read_set_options(a, "tar:!mac-ext");
    if (archive_read_open_filename(a, argv[1], 10240) != ARCHIVE_OK) {
        fprintf(stderr, "%s\n", archive_error_string(a));
        return 1;
    }
    struct archive_entry *e;
    int r;
    while ((r = archive_read_next_header(a, &e)) == ARCHIVE_OK || r == ARCHIVE_WARN) {
        uint64_t h = 0xcbf29ce484222325ULL, n = 0;
        const void *buf;
        size_t len;
        int64_t off;
        while (archive_read_data_block(a, &buf, &len, &off) == ARCHIVE_OK) {
            /* Holes before a block read as zeros, as hold's reader gives them. */
            for (; (int64_t)n < off; n++) h = (h ^ 0) * 0x100000001b3ULL;
            for (size_t i = 0; i < len; i++, n++) h = (h ^ ((const unsigned char *)buf)[i]) * 0x100000001b3ULL;
        }
        /* A file's trailing hole; other entries' size fields carry no data. */
        if (archive_entry_filetype(e) == AE_IFREG)
            for (; (int64_t)n < archive_entry_size(e); n++) h = (h ^ 0) * 0x100000001b3ULL;
        const char *link = archive_entry_hardlink(e) ? archive_entry_hardlink(e) : archive_entry_symlink(e);
        printf("%s %lld %o %lld %016llx %s\t%s\n", kind(e), (long long)n, archive_entry_perm(e) | (archive_entry_mode(e) & 07000),
               (long long)archive_entry_mtime(e), (unsigned long long)h, archive_entry_pathname(e), link ? link : "");
    }
    if (r != ARCHIVE_EOF) {
        printf("error %s\n", archive_error_string(a));
    }
    archive_read_free(a);
    return 0;
}
