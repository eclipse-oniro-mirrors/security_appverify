/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
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

#include "app_provision.h"
#include <stdbool.h>
#include <string.h>
#include "app_common.h"
#include "app_verify_hal.h"
#include "cJSON.h"
#include "securec.h"

const char APP_GALLERY[] = "app_gallery";
const char ENTERPRISE[] = "enterprise";
const char ENTERPRISE_NORMAL[] = "enterprise_normal";
const char ENTERPRISE_MDM[] = "enterprise_mdm";
const char OS_INTEGRATION[] = "os_integration";
const char INTERNALTESTING[] = "internaltesting";

static void ProfInit(ProfileProf *pf)
{
    errno_t ret = memset_s(pf, sizeof(ProfileProf), 0, sizeof(ProfileProf));
    if (ret != EOK) {
        LOG_ERROR("memset failed");
        return;
    }
    return;
}

static char *GetStringTag(const cJSON *root, const char *tag)
{
    cJSON *jsonObj = cJSON_GetObjectItem(root, tag);
    if ((jsonObj == NULL) || (jsonObj->valuestring == NULL)) {
        LOG_PRINT_STR("failed to get %s", tag);
        return NULL;
    }
    int32_t objLen = strlen(jsonObj->valuestring);
    if (objLen < 0) {
        LOG_PRINT_STR("len error");
        return NULL;
    }
    char *value = APPV_MALLOC(objLen + 1);
    if (value == NULL) {
        LOG_ERROR("malloc error: %d", objLen + 1);
        return NULL;
    }
    errno_t ret = strcpy_s(value, objLen + 1, jsonObj->valuestring);
    if (ret != EOK) {
        APPV_FREE(value);
        LOG_ERROR("strcpy error: %d", ret);
        return NULL;
    }
    return value;
}

static void FreeStringAttay(char **array, int32_t num)
{
    if (array == NULL) {
        return;
    }
    for (int32_t i = 0; i < num; i++) {
        if (array[i] != NULL) {
            APPV_FREE(array[i]);
        }
    }
    APPV_FREE(array);
    return;
}

static char **GetStringArrayTag(const cJSON *root, const char *tag, int32_t *numReturn)
{
    cJSON *jsonObj = cJSON_GetObjectItem(root, tag);
    if (jsonObj == NULL) {
        LOG_PRINT_STR("failed to get %s", tag);
        return NULL;
    }
    int32_t num = cJSON_GetArraySize(jsonObj);
    if (num == 0) {
        LOG_ERROR("array num 0");
        *numReturn = 0;
        return NULL;
    }
    char **value = APPV_MALLOC(sizeof(char *) * num);
    if (value == NULL) {
        LOG_ERROR("value is null");
        *numReturn = 0;
        return NULL;
    }
    (void)memset_s(value, sizeof(char *) * num, 0, sizeof(char *) * num);

    for (int32_t i = 0; i < num; i++) {
        cJSON *item = cJSON_GetArrayItem(jsonObj, i);
        P_NULL_GOTO_WTTH_LOG(item);
        if (item->valuestring == NULL) {
            LOG_ERROR("valuestring is NULL");
            FreeStringAttay(value, num);
            return NULL;
        }
        int32_t len = strlen(item->valuestring);
        value[i] = APPV_MALLOC(len + 1);
        P_NULL_GOTO_WTTH_LOG(value[i]);

        errno_t ret = strcpy_s(value[i], len + 1, item->valuestring);
        if (ret != EOK) {
            LOG_ERROR("str cpy error : %d", ret);
            FreeStringAttay(value, num);
            return NULL;
        }
    }
    *numReturn = num;
    return value;
EXIT:
    FreeStringAttay(value, num);
    return NULL;
}

static int32_t GetProfValidity(const cJSON *root, ProfValidity *profVal)
{
    cJSON *jsonObj = cJSON_GetObjectItem(root, "validity");
    if (jsonObj == NULL) {
        LOG_ERROR("failed to get validity");
        return V_ERR;
    }

    cJSON *notBefore = cJSON_GetObjectItem(jsonObj, "not-before");
    if (notBefore == NULL) {
        LOG_ERROR("failed to get not-before");
        return V_ERR;
    }
    profVal->notBefore = notBefore->valueint;

    cJSON *notAfter = cJSON_GetObjectItem(jsonObj, "not-after");
    if (notAfter == NULL) {
        LOG_ERROR("failed to get not-after");
        return V_ERR;
    }
    profVal->notAfter = notAfter->valueint;
    return V_OK;
}

static int32_t GetProfBundleInfo(const cJSON *root, ProfBundleInfo *profVal)
{
    cJSON *jsonObj = cJSON_GetObjectItem(root, "bundle-info");
    if (jsonObj == NULL) {
        LOG_ERROR("failed to get bundle-info");
        return V_ERR;
    }
    /* if failed, free by caller */
    profVal->developerId = GetStringTag(jsonObj, "developer-id");
    P_NULL_RETURN_WTTH_LOG(profVal->developerId);

    profVal->devCert = (unsigned char *)GetStringTag(jsonObj, "development-certificate");
    if (profVal->devCert == NULL) {
        LOG_ERROR("get development-certificat failed");
        profVal->devCert = APPV_MALLOC(sizeof(char));
        P_NULL_RETURN_WTTH_LOG(profVal->devCert);
        profVal->devCert[0] = '\0';
    }

    profVal->releaseCert = (unsigned char *)GetStringTag(jsonObj, "distribution-certificate");
    if (profVal->releaseCert == NULL) {
        LOG_ERROR("get distribution-certificat failed");
        profVal->releaseCert = APPV_MALLOC(sizeof(char));
        P_NULL_RETURN_WTTH_LOG(profVal->releaseCert);
        profVal->releaseCert[0] = '\0';
    }

    profVal->bundleName = GetStringTag(jsonObj, "bundle-name");
    P_NULL_RETURN_WTTH_LOG(profVal->bundleName);

    profVal->appFeature = GetStringTag(jsonObj, "app-feature");
    P_NULL_RETURN_WTTH_LOG(profVal->appFeature);

    return V_OK;
}

static int32_t GetProfPermission(const cJSON *root, ProfPermission *profVal)
{
    cJSON *jsonObj = cJSON_GetObjectItem(root, "permissions");
    if (jsonObj == NULL) {
        LOG_ERROR("failed to get permissions");
        return V_ERR;
    }
    profVal->permission = GetStringArrayTag(jsonObj, "feature-permissions", &profVal->permissionNum);
    profVal->restricPermission = GetStringArrayTag(jsonObj, "restricted-permissions", &profVal->restricNum);
    return V_OK;
}

static int32_t GetProfDebugInfo(const cJSON *root, ProfDebugInfo *profVal)
{
    cJSON *jsonObj = cJSON_GetObjectItem(root, "debug-info");
    if (jsonObj == NULL) {
        LOG_INFO("failed to get debug-info");
        return V_OK;
    }
    profVal->devIdType = GetStringTag(jsonObj, "device-id-type");
    if (profVal->devIdType == NULL) {
        LOG_INFO("failed to get device-id-type");
        return V_OK;
    }
    profVal->deviceId = GetStringArrayTag(jsonObj, "device-ids", &profVal->devidNum);
    return V_OK;
}

static int32_t GetProfIssuerInfo(const cJSON *root, ProfileProf *pf)
{
    pf->issuer = GetStringTag(root, "issuer");
    if (pf->issuer == NULL) {
        int32_t len = strlen(APP_STORE);
        pf->issuer = APPV_MALLOC(len + 1);
        if (pf->issuer == NULL) {
            return V_ERR;
        }
        errno_t ret = strcpy_s(pf->issuer, len + 1, APP_STORE);
        if (ret != EOK) {
            APPV_FREE(pf->issuer);
            LOG_ERROR("str cpy error: %d", ret);
        }
        return ret;
    }
    return V_OK;
}

static void FreeProfBundle(ProfBundleInfo *pfval)
{
    FREE_IF_NOT_NULL(pfval->appFeature);
    FREE_IF_NOT_NULL(pfval->bundleName);
    FREE_IF_NOT_NULL(pfval->devCert);
    FREE_IF_NOT_NULL(pfval->developerId);
    FREE_IF_NOT_NULL(pfval->releaseCert);
    return;
}

static void FreeProfPerssion(ProfPermission *pfval)
{
    FreeStringAttay(pfval->permission, pfval->permissionNum);
    pfval->permissionNum = 0;
    pfval->permission = NULL;

    FreeStringAttay(pfval->restricPermission, pfval->restricNum);
    pfval->restricNum = 0;
    pfval->restricPermission = NULL;
    return;
}

static void FreeProfDebuginfo(ProfDebugInfo *pfval)
{
    FREE_IF_NOT_NULL(pfval->devIdType);

    FreeStringAttay(pfval->deviceId, pfval->devidNum);
    pfval->devidNum = 0;
    pfval->deviceId = NULL;

    return;
}

void ProfFreeData(ProfileProf *pf)
{
    if (pf == NULL) {
        return;
    }
    FREE_IF_NOT_NULL(pf->versionName);
    FREE_IF_NOT_NULL(pf->uuid);
    FREE_IF_NOT_NULL(pf->type);
    FREE_IF_NOT_NULL(pf->appDistType);
    FreeProfBundle(&pf->bundleInfo);
    FreeProfPerssion(&pf->permission);
    FreeProfDebuginfo(&pf->debugInfo);
    FREE_IF_NOT_NULL(pf->issuer);
    FREE_IF_NOT_NULL(pf->appid);
    return;
}

/* parse profile */
int32_t ParseProfile(const char *buf, int32_t len, ProfileProf *pf)
{
    P_NULL_RETURN_WTTH_LOG(pf);
    P_NULL_RETURN_WTTH_LOG(buf);
    ProfInit(pf);
    int32_t ret;
    char *pfStr = strchr(buf, '{');
    P_NULL_RETURN_WTTH_LOG(pfStr);

    cJSON *root = cJSON_Parse(pfStr);
    P_NULL_RETURN_WTTH_LOG(root);

    cJSON *jsonObj = cJSON_GetObjectItem(root, "version-code");
    P_NULL_GOTO_WTTH_LOG(jsonObj);
    pf->versionCode = jsonObj->valueint;

    pf->versionName = GetStringTag(root, "version-name");
    P_NULL_GOTO_WTTH_LOG(pf->versionName);

    pf->uuid = GetStringTag(root, "uuid");
    P_NULL_GOTO_WTTH_LOG(pf->uuid);

    pf->type = GetStringTag(root, "type");
    P_NULL_GOTO_WTTH_LOG(pf->type);

    pf->appDistType = GetStringTag(root, "app-distribution-type");
    if (pf->appDistType == NULL) {
        pf->appDistType = APPV_MALLOC(sizeof(char));
        P_NULL_GOTO_WTTH_LOG(pf->appDistType);
        pf->appDistType[0] = '\0';
    }

    ret = GetProfValidity(root, &pf->validity);
    P_ERR_GOTO_WTTH_LOG(ret);

    ret = GetProfBundleInfo(root, &pf->bundleInfo);
    P_ERR_GOTO_WTTH_LOG(ret);

    ret = GetProfPermission(root, &pf->permission);
    P_ERR_GOTO_WTTH_LOG(ret);

    ret = GetProfDebugInfo(root, &pf->debugInfo);
    P_ERR_GOTO_WTTH_LOG(ret);

    ret = GetProfIssuerInfo(root, pf);
    P_ERR_GOTO_WTTH_LOG(ret);

    LOG_INFO("parse profile json success");
    cJSON_Delete(root);
    return V_OK;

EXIT:
    cJSON_Delete(root);
    ProfFreeData(pf);
    return V_ERR;
}

static int32_t VerifyAppTypeAndDistribution(const ProfileProf *pf)
{
    if ((strcmp(pf->type, DEBUG_TYPE) != 0) && (strcmp(pf->type, RELEASE_TYPE) != 0)) {
        LOG_PRINT_STR("invalid app type: %s", pf->type);
        return V_ERR;
    }
    if (strcmp(pf->type, RELEASE_TYPE) == 0) {
        if ((strcmp(pf->appDistType, APP_GALLERY) != 0) && (strcmp(pf->appDistType, ENTERPRISE) != 0) &&
            (strcmp(pf->appDistType, ENTERPRISE_NORMAL) != 0) && (strcmp(pf->appDistType, ENTERPRISE_MDM) != 0) &&
            (strcmp(pf->appDistType, INTERNALTESTING) != 0) && (strcmp(pf->appDistType, OS_INTEGRATION) != 0)) {
            LOG_PRINT_STR("invalid app dis type: %s", pf->appDistType);
            return V_ERR;
        }
    }
    return V_OK;
}

static int32_t VerifyAppBundleInfo(const ProfileProf *pf)
{
    if (strcmp(pf->type, DEBUG_TYPE) == 0) {
        if (strlen((char *)pf->bundleInfo.devCert) == 0) {
            LOG_ERROR("debug app, dev cert null");
            return V_ERR;
        }
    } else if (strcmp(pf->type, RELEASE_TYPE) == 0) {
        if (strlen((char *)pf->bundleInfo.releaseCert) == 0) {
            LOG_ERROR("debug app, dev cert null");
            return V_ERR;
        }
    } else {
        LOG_PRINT_STR("invalid app type: %s", pf->type);
        return V_ERR;
    }
    return V_OK;
}

static int32_t VerifyUdid(const ProfileProf *pf)
{
    uint32_t size = UDID_VERIFY_BYTES + 1;
    if (pf->debugInfo.devidNum > MAX_UDID_NUM) {
        LOG_ERROR("udid num exceed maximum");
        return V_ERR;
    }
    unsigned char *udid = APPV_MALLOC(size);
    if (udid == NULL) {
        LOG_ERROR("udid is null");
        return V_ERR;
    }
    (void)memset_s(udid, size, 0, size);
    int32_t result = InquiryDeviceUdid(udid, size);
    if (result != INQUIRY_UDID_OK) {
        free(udid);
        LOG_ERROR("get udid fail, ret: %d", result);
        return V_ERR;
    }
    for (int32_t i = 0; i < pf->debugInfo.devidNum; i++) {
        if (strcmp((const char *)pf->debugInfo.deviceId[i], (const char *)udid) == 0) {
            LOG_INFO("find right udid");
            free(udid);
            udid = NULL;
            return V_OK;
        }
    }
    LOG_ERROR("udid invalid");
    free(udid);
    udid = NULL;
    return V_ERR;
}

static int32_t VerifyDebugInfo(const ProfileProf *pf)
{
    if (strcmp(pf->type, DEBUG_TYPE) != 0) {
        LOG_INFO("not debug app, return ok");
        return V_OK;
    }
    LOG_PRINT_STR("devid type: %s", pf->debugInfo.devIdType);
    int32_t ret;
    if (strcmp(pf->debugInfo.devIdType, "udid") == 0) {
        ret = VerifyUdid(pf);
    } else {
        LOG_ERROR("devid type invalid");
        ret = V_ERR;
    }
    return ret;
}

int32_t VerifyProfileContent(const ProfileProf *pf)
{
    P_NULL_RETURN_WTTH_LOG(pf);
    int32_t ret = VerifyAppTypeAndDistribution(pf);
    if (ret != V_OK) {
        LOG_PRINT_STR("invalid profile distribution type : %s", pf->appDistType);
        return V_ERR_INVALID_DISP_TYPE;
    }
    ret = VerifyAppBundleInfo(pf);
    if (ret != V_OK) {
        LOG_ERROR("invalid profile app bundle info");
        return V_ERR_INVALID_APP_BUNDLE;
    }
    /* verify debug device id */
    ret = VerifyDebugInfo(pf);
    if (ret != V_OK) {
        LOG_ERROR("validate debug info");
        return V_ERR_INVALID_DEVID;
    }
    return V_OK;
}
