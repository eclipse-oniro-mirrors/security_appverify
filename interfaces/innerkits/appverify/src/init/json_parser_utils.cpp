/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "init/json_parser_utils.h"

#include <fstream>
#include <sstream>

#include "common/hap_verify_log.h"

namespace OHOS {
namespace Security {
namespace Verify {
bool JsonParserUtils::ReadTrustedRootCAFromJson(cJSON** jsonObj,
    const std::string& jsonPath, std::string& error)
{
    std::ifstream jsonFileStream;
    jsonFileStream.open(jsonPath.c_str(), std::ios::in);
    if (!jsonFileStream.is_open()) {
        error += "open file failed";
        return false;
    }
    std::ostringstream buf;
    char ch;
    while (buf && jsonFileStream.get(ch)) {
        buf.put(ch);
    }
    jsonFileStream.close();

    std::string jsonStr = buf.str();
    *jsonObj = cJSON_Parse(jsonStr.c_str());
    if (*jsonObj == NULL) {
        error += "parse jsonStr failed";
        return false;
    }
    return true;
}

bool JsonParserUtils::GetJsonString(const cJSON* json, const std::string& key, std::string& value)
{
    if (json == NULL || !cJSON_IsObject(json)) {
        return false;
    }
    cJSON* jsonValue = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    if (jsonValue != NULL && cJSON_IsString(jsonValue)) {
        value = jsonValue->valuestring;
    }
    return true;
}

bool JsonParserUtils::GetJsonInt(const cJSON* json, const std::string& key, int& value)
{
    if (json == NULL || !cJSON_IsObject(json)) {
        return false;
    }
    cJSON* jsonValue = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    if (jsonValue != NULL && cJSON_IsNumber(jsonValue)) {
        value = jsonValue->valueint;
    }
    return true;
}

bool JsonParserUtils::GetJsonStringVec(const cJSON* json, const std::string& key, StringVec& value)
{
    if (json == NULL || !cJSON_IsObject(json)) {
        return false;
    }
    cJSON* jsonArray = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    if (jsonArray == NULL || !cJSON_IsArray(jsonArray)) {
        return false;
    }
    cJSON* item = NULL;
    cJSON_ArrayForEach(item, jsonArray) {
        if (item != NULL && cJSON_IsString(item)) {
            value.emplace_back(item->valuestring);
        }
    }
    return true;
}

bool JsonParserUtils::ParseJsonToObjVec(const cJSON* json, const std::string& key, JsonObjVec& jsonObjVec)
{
    if (json == NULL || !cJSON_IsObject(json)) {
        return false;
    }
    cJSON* jsonArray = cJSON_GetObjectItemCaseSensitive(json, key.c_str());
    if (jsonArray == NULL || !cJSON_IsArray(jsonArray)) {
        return false;
    }
    cJSON* item = NULL;
    cJSON_ArrayForEach(item, jsonArray) {
        if (item != NULL && cJSON_IsObject(item)) {
            jsonObjVec.emplace_back(item);
        }
    }
    return true;
}

void JsonParserUtils::ParseJsonToMap(const cJSON* json, JsonMap& jsonMap)
{
    if (json == NULL || !cJSON_IsObject(json)) {
        return;
    }
    cJSON* item = NULL;
    cJSON_ArrayForEach(item, json) {
        if (item != NULL && cJSON_IsString(item)) {
            std::string key = item->string;
            std::string value = item->valuestring;
            jsonMap[key] = value;
        }
    }
}
} // namespace Verify
} // namespace Security
} // namespace OHOS
