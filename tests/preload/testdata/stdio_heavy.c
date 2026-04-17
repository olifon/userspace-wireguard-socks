/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int write_lines(FILE *fp) {
    char line[256];
    for (int i = 0; i < 256; i++) {
        snprintf(line, sizeof(line), "row=%03d alpha=%d beta=%d gamma=%d\n", i, i * 3, i * 5, i * 7);
        if (fprintf(fp, "%s", line) < 0) {
            perror("fprintf");
            return 1;
        }
        if (fwrite("payload-block\n", 1, strlen("payload-block\n"), fp) != strlen("payload-block\n")) {
            perror("fwrite");
            return 1;
        }
    }
    if (fflush(fp) != 0) {
        perror("fflush");
        return 1;
    }
    if (fsync(fileno(fp)) != 0) {
        perror("fsync");
        return 1;
    }
    return 0;
}

static int read_back(FILE *fp, size_t *lines_seen, size_t *bytes_seen) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, fp)) >= 0) {
        *lines_seen += 1;
        *bytes_seen += (size_t)n;
        if (line[0] == 'r') {
            if (ungetc(line[0], fp) == EOF) {
                perror("ungetc");
                free(line);
                return 1;
            }
            if (fgetc(fp) != line[0]) {
                fprintf(stderr, "fgetc after ungetc mismatch\n");
                free(line);
                return 1;
            }
        }
    }
    if (!feof(fp)) {
        perror("getline");
        free(line);
        return 1;
    }
    free(line);
    return 0;
}

static int scandir_count(const char *dir, int *count) {
    DIR *dp = opendir(dir);
    if (dp == NULL) {
        perror("opendir");
        return 1;
    }
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        *count += 1;
    }
    if (closedir(dp) != 0) {
        perror("closedir");
        return 1;
    }
    return 0;
}

static int do_baseline(void) {
    puts("stdio-baseline-ok");
    return 0;
}

static int do_heavy(void) {
    char dir_template[] = "/tmp/uwgs-stdio-heavy-XXXXXX";
    char *dir = mkdtemp(dir_template);
    if (dir == NULL) {
        perror("mkdtemp");
        return 1;
    }

    char data_path[PATH_MAX];
    char renamed_path[PATH_MAX];
    snprintf(data_path, sizeof(data_path), "%s/data.txt", dir);
    snprintf(renamed_path, sizeof(renamed_path), "%s/data-renamed.txt", dir);

    FILE *fp = fopen(data_path, "w+");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    if (setvbuf(fp, NULL, _IOFBF, 32 * 1024) != 0) {
        perror("setvbuf");
        fclose(fp);
        return 1;
    }
    if (write_lines(fp) != 0) {
        fclose(fp);
        return 1;
    }

    long end = ftell(fp);
    if (end <= 0) {
        fprintf(stderr, "ftell returned %ld\n", end);
        fclose(fp);
        return 1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(fp);
        return 1;
    }

    size_t lines_seen = 0;
    size_t bytes_seen = 0;
    if (read_back(fp, &lines_seen, &bytes_seen) != 0) {
        fclose(fp);
        return 1;
    }
    if (lines_seen == 0 || bytes_seen == 0) {
        fprintf(stderr, "unexpected empty file readback\n");
        fclose(fp);
        return 1;
    }
    fclose(fp);

    if (rename(data_path, renamed_path) != 0) {
        perror("rename");
        return 1;
    }

    struct stat st;
    if (stat(renamed_path, &st) != 0) {
        perror("stat");
        return 1;
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "unexpected stat size %lld\n", (long long)st.st_size);
        return 1;
    }

    char resolved[PATH_MAX];
    if (realpath(renamed_path, resolved) == NULL) {
        perror("realpath");
        return 1;
    }

    int fd = open(resolved, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    FILE *fd_fp = fdopen(fd, "r");
    if (fd_fp == NULL) {
        perror("fdopen");
        close(fd);
        return 1;
    }
    char chunk[1024];
    size_t total = 0;
    while (!feof(fd_fp)) {
        size_t n = fread(chunk, 1, sizeof(chunk), fd_fp);
        total += n;
        if (ferror(fd_fp)) {
            perror("fread");
            fclose(fd_fp);
            return 1;
        }
    }
    fclose(fd_fp);
    if (total == 0) {
        fprintf(stderr, "unexpected zero fread total\n");
        return 1;
    }

    int entries = 0;
    if (scandir_count(dir, &entries) != 0) {
        return 1;
    }
    if (entries != 1) {
        fprintf(stderr, "unexpected directory entry count %d\n", entries);
        return 1;
    }

    if (unlink(renamed_path) != 0) {
        perror("unlink");
        return 1;
    }
    if (rmdir(dir) != 0) {
        perror("rmdir");
        return 1;
    }

    puts("stdio-heavy-ok");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "baseline") == 0) {
        return do_baseline();
    }
    return do_heavy();
}
