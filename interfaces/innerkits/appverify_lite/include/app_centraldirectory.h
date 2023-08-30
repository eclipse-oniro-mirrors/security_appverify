/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURITY_APP_CENTRALDIECTORY_H
#define SECURITY_APP_CENTRALDIECTORY_H

#include <stdint.h>

#include "mbedtls/pk.h"
#include "app_verify_pub.h"
#include "app_file.h"
#include "app_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define HAP_SIG_BLOCK_MAGIC_HI_OLD 3617552046287187010LL
#define HAP_SIG_BLOCK_MAGIC_LO_OLD 2334950737560224072LL
#define HAP_SIG_BLOCK_MAGIC_HI 4497797983070462062LL
#define HAP_SIG_BLOCK_MAGIC_LO 7451613641622775868LL
#define HAP_SIG_BLOCK_MIN_SIZE 32
#define UINT16_MAX_VALUE 0xffff
#define HAP_EOCD_MAGIC 0x06054b50
#define HAP_FIRST_LEVEL_CHUNK_PREFIX 0x5a
#define HAP_SECOND_LEVEL_CHUNK_PREFIX 0xa5
#define VERSION_FOR_NEW_MAGIC_NUM 3

typedef struct {
    void *buffer;
    int32_t len;
} HapBuf;

#pragma pack(4)
/* hw sign head */
typedef struct {
    uint32_t blockNum;
    unsigned long long size;
    unsigned long long magicLow;
    unsigned long long magicHigh;
    uint32_t version;
} HwSignHead;
#pragma pack()

#pragma pack(2)
typedef struct {
    int32_t magic;
    short diskNum;
    short startNum;
    short coreDirNumOnDisk;
    short coreDirNum;
    int32_t coreDirSize;
    int32_t coreDirOffset;
    short commentLen;
} MinEocd;
#pragma pack()

typedef struct {
    MinEocd eocdHead;
    char *comment;
} HapEocd;

typedef struct {
    HwSignHead *signHead;
    int32_t fullSignBlockOffset;
    int32_t hapCoreDirOffset;
    int32_t hapEocdOffset;
    int32_t hapEocdSize;
    int32_t fileSize;
    int32_t version;
    int32_t certType;
} SignatureInfo;

bool FindSignature(const FileRead *hapFile, SignatureInfo *signInfo);
bool CreateHapBuffer(HapBuf *hapBuffer, int32_t len);
int32_t ReadFileFullyFromOffset(const HapBuf *buffer, int32_t offset, const FileRead *file);
void HapSetInt32(const HapBuf *buffer, int32_t offset, int32_t value);
void ClearHapBuffer(HapBuf *hapBuffer);
void HapPutByte(const HapBuf *hapBuffer, int32_t offset, char value);
void HapPutData(const HapBuf *hapBuffer, int32_t offset, const unsigned char *data, int32_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
