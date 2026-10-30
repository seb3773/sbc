#ifndef SBC_H
#define SBC_H

#include <stddef.h>
#include <stdint.h>

#define SBC_MAGIC_LEN 5
#define SBC_MAX_NAME 512
#define SBC_MAX_FILES 4096

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} SbcReader;

typedef struct {
    SbcReader *rdr;
    uint32_t low;
    uint32_t range;
    uint32_t code;
    int err;
} SbcRC;

typedef struct {
    SbcRC *rc;
    uint32_t *freq;
    uint32_t nsyms;
    uint32_t cap;
    uint32_t total;
    uint32_t inc;
    uint32_t cap_freq;
    uint32_t cap_tot;
} SbcExtra;

typedef struct {
    SbcExtra extra;
    uint32_t last;
    uint32_t count;
    uint32_t c12;
} SbcSizeModel;

typedef struct {
    char name[SBC_MAX_NAME];
    uint32_t flag;
    uint32_t dt;
    uint32_t size;
} SbcFileEnt;

typedef struct {
    uint32_t crypto;
    uint32_t csum;
    uint32_t solid;
    uint32_t nfiles;
    uint32_t method;
    uint32_t extra3;
    SbcFileEnt *files;
    size_t hdr_pos;
    int err;
} SbcHeader;

typedef struct {
    uint8_t *data;
    size_t len;
    char name[SBC_MAX_NAME];
    uint32_t dt;
} SbcExtracted;

int sbc_decode_archive(const uint8_t *data, size_t len,
                       SbcExtracted **out, uint32_t *n_out);

void sbc_free_extracted(SbcExtracted *files, uint32_t n);

#endif
