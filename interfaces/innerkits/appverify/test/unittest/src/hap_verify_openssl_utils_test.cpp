/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "hap_verify_openssl_utils_test.h"

#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "openssl/x509.h"

#include "common/hap_byte_buffer.h"
#include "util/hap_verify_openssl_utils.h"

using namespace testing::ext;
using namespace OHOS::Security::Verify;

namespace {
class HapVerifyOpensslUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HapVerifyOpensslUtilsTest::SetUpTestCase(void)
{
}

void HapVerifyOpensslUtilsTest::TearDownTestCase(void)
{
}
void HapVerifyOpensslUtilsTest::SetUp()
{
}

void HapVerifyOpensslUtilsTest::TearDown()
{
}

// ---- minimal DER encoder for GetPkcs7ContentByAsn1 branch-coverage tests ----
constexpr unsigned char DER_TAG_SEQUENCE = 0x30;       // constructed SEQUENCE
constexpr unsigned char DER_TAG_SET = 0x31;             // constructed SET
constexpr unsigned char DER_TAG_INTEGER = 0x02;         // primitive INTEGER
constexpr unsigned char DER_TAG_OID = 0x06;             // primitive OBJECT IDENTIFIER
constexpr unsigned char DER_TAG_OCTET_STRING = 0x04;    // primitive OCTET STRING
constexpr unsigned char DER_TAG_CONTEXT_0 = 0xA0;       // constructed [0] EXPLICIT
constexpr unsigned char DER_TAG_CONTEXT_1 = 0xA1;       // constructed [1] EXPLICIT

// 1.2.840.113549.1.7.2 (signedData) and 1.2.840.113549.1.7.1 (data), DER OID content bytes.
const unsigned char DER_SIGNED_DATA_OID[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};
const unsigned char DER_DATA_OID[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
};

// Opaque non-empty filler; Pkcs7ProfileParser only checks object header/tag/length, never inner bytes.
const std::string DER_FILLER = "x";

void AppendDerLength(std::string& out, size_t len)
{
    if (len < 0x80) {
        out.push_back(static_cast<char>(len));
        return;
    }
    std::string lenBytes;
    size_t remain = len;
    while (remain > 0) {
        lenBytes.push_back(static_cast<char>(remain & 0xFF));
        remain >>= 8;
    }
    std::reverse(lenBytes.begin(), lenBytes.end());
    out.push_back(static_cast<char>(0x80 | lenBytes.size()));
    out.append(lenBytes);
}

std::string DerWrap(unsigned char tag, const std::string& content)
{
    std::string out;
    out.push_back(static_cast<char>(tag));
    AppendDerLength(out, content.size());
    out.append(content);
    return out;
}

std::string DerSequence(const std::string& content) { return DerWrap(DER_TAG_SEQUENCE, content); }
std::string DerSet(const std::string& content) { return DerWrap(DER_TAG_SET, content); }
std::string DerInteger(const std::string& content) { return DerWrap(DER_TAG_INTEGER, content); }
std::string DerOctetString(const std::string& content) { return DerWrap(DER_TAG_OCTET_STRING, content); }
std::string DerExplicit0(const std::string& content) { return DerWrap(DER_TAG_CONTEXT_0, content); }
std::string DerExplicit1(const std::string& content) { return DerWrap(DER_TAG_CONTEXT_1, content); }
std::string DerOid(const unsigned char* oid, size_t len)
{
    return DerWrap(DER_TAG_OID, std::string(reinterpret_cast<const char*>(oid), len));
}

std::string BuildEncapsulatedContentInfo(const std::string& profile)
{
    return DerSequence(DerOid(DER_DATA_OID, sizeof(DER_DATA_OID)) +
        DerExplicit0(DerOctetString(profile)));
}

// signerInfos is the final required SET; the parser only verifies it is a non-empty SET.
std::string BuildSignerInfosTail()
{
    return DerSet(DER_FILLER);
}

std::string BuildSignedData(const std::string& profile, const std::string& tail)
{
    std::string content;
    content += DerInteger("\x03");            // version = 3
    content += DerSet(DER_FILLER);            // digestAlgorithms (length > 0)
    content += BuildEncapsulatedContentInfo(profile);
    content += tail;
    return DerSequence(content);
}

std::string BuildContentInfo(const std::string& signedData)
{
    return DerSequence(DerOid(DER_SIGNED_DATA_OID, sizeof(DER_SIGNED_DATA_OID)) +
        DerExplicit0(signedData));
}

std::string BuildValidPkcs7(const std::string& profile)
{
    return BuildContentInfo(BuildSignedData(profile, BuildSignerInfosTail()));
}

HapByteBuffer BuildPkcs7Buffer(const std::string& der)
{
    HapByteBuffer buffer(static_cast<int32_t>(der.size()));
    buffer.PutData(0, der.data(), static_cast<int32_t>(der.size()));
    return buffer;
}

/**
 * @tc.name: Test VerifyPkcs7 functions
 * @tc.desc: use invalid input to verify pkcs7, The function will return false;
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, VerifyPkcs7_001, TestSize.Level2)
{
    /*
     * @tc.steps: step1. use a null input to run OpensslVerifyPkcs7
     * @tc.expected: step1. the return will be false.
     */
    Pkcs7Context digest;
    ASSERT_FALSE(HapVerifyOpensslUtils::VerifyPkcs7SignedData(digest));
    ASSERT_FALSE(HapVerifyOpensslUtils::VerifySignInfo(nullptr, nullptr, 0, digest));
    ASSERT_FALSE(HapVerifyOpensslUtils::VerifyShaWithRsaPss(nullptr, nullptr, true, nullptr, 0));
    std::vector<std::string> publicKeyVec;
    ASSERT_FALSE(HapVerifyOpensslUtils::GetPublickeyFromCertificate(nullptr, publicKeyVec));
}

/**
 * @tc.name: Test GetDigestAlgorithmId functions
 * @tc.desc: use different algorithm IDs to run this function, The function will return nid
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetDigestAlgorithmId001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. use different algorithm IDs to run OpensslVerifyPkcs7
     * @tc.expected: step1. the return will be nID.
     */
    int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(ALGORITHM_SHA512_WITH_RSA_PSS);
    ASSERT_TRUE(nId == TEST_SHA512_NID);
    nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(ALGORITHM_SHA384_WITH_RSA_PSS);
    ASSERT_TRUE(nId == TEST_SHA384_NID);
    nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(ALGORITHM_SHA256_WITH_RSA_PSS);
    ASSERT_TRUE(nId == TEST_SHA256_NID);
    nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(0);
    ASSERT_TRUE(nId == 0);
}

/**
 * @tc.name: Test ParsePkcs7Package functions
 * @tc.desc: ParsePkcs7Package
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, ParsePkcs7Package_0100, TestSize.Level1)
{
    unsigned char packageData[] = "test";
    uint32_t packageLen = 1;
    Pkcs7Context pkcs7Context;
    auto ret = HapVerifyOpensslUtils::ParsePkcs7Package(packageData, packageLen, pkcs7Context);
    EXPECT_FALSE(ret);
    ret = HapVerifyOpensslUtils::ParsePkcs7Package(nullptr, packageLen, pkcs7Context);
    EXPECT_FALSE(ret);
    packageLen = 0;
    ret = HapVerifyOpensslUtils::ParsePkcs7Package(packageData, packageLen, pkcs7Context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetCertChains functions
 * @tc.desc: GetCertChains
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetCertChains_0100, TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    auto ret = HapVerifyOpensslUtils::GetCertChains(nullptr, pkcs7Context);
    EXPECT_NE(ret, VERIFY_SUCCESS);
}

/**
 * @tc.name: Test VerifyPkcs7 functions
 * @tc.desc: VerifyPkcs7
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, VerifyPkcs7_0100, TestSize.Level1)
{
    HapVerifyOpensslUtils hapVerifyOpensslUtils;
    Pkcs7Context pkcs7Context;
    pkcs7Context.p7 = nullptr;
    auto ret = hapVerifyOpensslUtils.VerifyPkcs7(pkcs7Context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0100, TestSize.Level1)
{
    unsigned char data[] = "";
    int32_t len = 0;
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(nullptr, data, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0200, TestSize.Level1)
{
    unsigned char data[] = "";
    int32_t len = 0;
    ASN1_OCTET_STRING asnStr;
    asnStr.data = nullptr;
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, data, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0300, TestSize.Level1)
{
    int32_t len = 0;
    unsigned char data[] = "c";
    ASN1_OCTET_STRING asnStr = {1, 1, data, 1};
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, nullptr, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0400, TestSize.Level1)
{
    int32_t len = 0;
    unsigned char data[] = "c";
    ASN1_OCTET_STRING asnStr = {1, 1, data, 1};
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, data, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test AsnStringCmp functions
 * @tc.desc: AsnStringCmp
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, AsnStringCmp_0500, TestSize.Level1)
{
    int32_t len = 1;
    unsigned char data[] = "c";
    unsigned char buf[] = "a";
    ASN1_OCTET_STRING asnStr = {1, 1, data, 1};
    auto ret = HapVerifyOpensslUtils::AsnStringCmp(&asnStr, buf, len);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetPublickeys functions
 * @tc.desc: GetPublickeys
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPublickeys_0100, TestSize.Level1)
{
    CertChain signCertChain;
    signCertChain.emplace_back(nullptr);
    std::vector<std::string> SignatureVec;
    auto ret = HapVerifyOpensslUtils::GetPublickeys(signCertChain, SignatureVec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetSignatures functions
 * @tc.desc: GetSignatures
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetSignatures_0100, TestSize.Level1)
{
    CertChain signCertChain;
    signCertChain.emplace_back(nullptr);
    std::vector<std::string> SignatureVec;
    auto ret = HapVerifyOpensslUtils::GetSignatures(signCertChain, SignatureVec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: Test GetDerCert functions
 * @tc.desc: GetDerCert
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetDerCert_0100, TestSize.Level1)
{
    std::vector<std::string> SignatureVec;
    auto ret = HapVerifyOpensslUtils::GetDerCert(nullptr, SignatureVec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetPkcs7ContentByAsn1_0100
 * @tc.desc: GetPkcs7ContentByAsn1 extracts profile JSON from a valid fixed-path PKCS#7,
 *           and rejects empty / single-byte garbage buffers.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPkcs7ContentByAsn1_0100, TestSize.Level1)
{
    const std::string profile = "{\"app-name\":\"demo\",\"version\":3}";
    std::string content;

    /*
     * @tc.steps: step1. feed a valid signedData whose encapContentInfo carries the profile JSON.
     * @tc.expected: step1. returns true and content equals the original profile JSON.
     */
    HapByteBuffer valid = BuildPkcs7Buffer(BuildValidPkcs7(profile));
    EXPECT_TRUE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(valid, content));
    EXPECT_EQ(content, profile);

    /*
     * @tc.steps: step2. feed a default-constructed (capacity 0) buffer.
     * @tc.expected: step2. returns false via the invalid-pkcs7-block guard.
     */
    HapByteBuffer empty;
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(empty, content));

    /*
     * @tc.steps: step3. feed a single byte that cannot even form an ASN.1 header.
     * @tc.expected: step3. returns false via the ASN1_get_object error path in ReadObject.
     */
    HapByteBuffer garbage = BuildPkcs7Buffer("X");
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(garbage, content));
}

/**
 * @tc.name: GetPkcs7ContentByAsn1_0200
 * @tc.desc: GetPkcs7ContentByAsn1 rejects malformed outer ContentInfo structures.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPkcs7ContentByAsn1_0200, TestSize.Level1)
{
    const std::string profile = "{\"app\":\"demo\"}";
    std::string content;
    const std::string validSignedData = BuildSignedData(profile, BuildSignerInfosTail());

    // outermost object is not a constructed SEQUENCE (bare OID).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(
        BuildPkcs7Buffer(DerOid(DER_SIGNED_DATA_OID, sizeof(DER_SIGNED_DATA_OID))), content));

    // trailing bytes after the outer SEQUENCE -> cursor does not reach dataEnd.
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(
        BuildPkcs7Buffer(BuildValidPkcs7(profile) + "X"), content));

    // wrong contentType OID (data OID where signedData OID is expected).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(DerSequence(
        DerOid(DER_DATA_OID, sizeof(DER_DATA_OID)) + DerExplicit0(validSignedData))), content));

    // signedData is not wrapped in [0] EXPLICIT.
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(DerSequence(
        DerOid(DER_SIGNED_DATA_OID, sizeof(DER_SIGNED_DATA_OID)) + validSignedData)), content));

    // trailing bytes inside ContentInfo after the [0] wrapper.
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(DerSequence(
        DerOid(DER_SIGNED_DATA_OID, sizeof(DER_SIGNED_DATA_OID)) + DerExplicit0(validSignedData) + "X")),
        content));
}

/**
 * @tc.name: GetPkcs7ContentByAsn1_0300
 * @tc.desc: GetPkcs7ContentByAsn1 rejects malformed SignedData headers.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPkcs7ContentByAsn1_0300, TestSize.Level1)
{
    const std::string profile = "{\"app\":\"demo\"}";
    std::string content;

    auto wrapSignedData = [&profile](const std::string& version, const std::string& digestAlgos,
        const std::string& encap) {
        std::string body;
        body += version;
        body += digestAlgos;
        body += encap;
        body += BuildSignerInfosTail();
        return BuildContentInfo(DerSequence(body));
    };

    // version is not an INTEGER (OCTET STRING instead).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapSignedData(
        DerOctetString("\x03"), DerSet(DER_FILLER), BuildEncapsulatedContentInfo(profile))), content));

    // digestAlgorithms is not a SET (SEQUENCE instead).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapSignedData(
        DerInteger("\x03"), DerSequence(DER_FILLER), BuildEncapsulatedContentInfo(profile))), content));

    // encapContentInfo is not a SEQUENCE (SET instead).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapSignedData(
        DerInteger("\x03"), DerSet(DER_FILLER),
        DerSet(DerOid(DER_DATA_OID, sizeof(DER_DATA_OID)) + DerExplicit0(DerOctetString(profile))))),
        content));

    // version has zero length.
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapSignedData(
        DerInteger(""), DerSet(DER_FILLER), BuildEncapsulatedContentInfo(profile))), content));

    // digestAlgorithms has zero length.
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapSignedData(
        DerInteger("\x03"), DerSet(""), BuildEncapsulatedContentInfo(profile))), content));
}

/**
 * @tc.name: GetPkcs7ContentByAsn1_0400
 * @tc.desc: GetPkcs7ContentByAsn1 rejects malformed encapsulated content info.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPkcs7ContentByAsn1_0400, TestSize.Level1)
{
    const std::string profile = "{\"app\":\"demo\"}";
    std::string content;

    auto wrapEncap = [&profile](const std::string& encap) {
        std::string body;
        body += DerInteger("\x03");
        body += DerSet(DER_FILLER);
        body += encap;
        body += BuildSignerInfosTail();
        return BuildContentInfo(DerSequence(body));
    };

    // wrong eContentType OID (signedData OID instead of data OID).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapEncap(
        DerSequence(DerOid(DER_SIGNED_DATA_OID, sizeof(DER_SIGNED_DATA_OID)) +
        DerExplicit0(DerOctetString(profile))))), content));

    // eContent is not wrapped in [0] (use [1] instead).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapEncap(
        DerSequence(DerOid(DER_DATA_OID, sizeof(DER_DATA_OID)) +
        DerExplicit1(DerOctetString(profile))))), content));

    // eContent is not an OCTET STRING (SEQUENCE instead).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapEncap(
        DerSequence(DerOid(DER_DATA_OID, sizeof(DER_DATA_OID)) +
        DerExplicit0(DerSequence(profile))))), content));

    // empty profile OCTET STRING.
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(wrapEncap(
        DerSequence(DerOid(DER_DATA_OID, sizeof(DER_DATA_OID)) + DerExplicit0(DerOctetString(""))))),
        content));
}

/**
 * @tc.name: GetPkcs7ContentByAsn1_0500
 * @tc.desc: GetPkcs7ContentByAsn1 rejects malformed SignedData tails (signerInfos validation).
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPkcs7ContentByAsn1_0500, TestSize.Level1)
{
    const std::string profile = "{\"app\":\"demo\"}";
    std::string content;

    auto wrapTail = [&profile](const std::string& tail) {
        return BuildContentInfo(BuildSignedData(profile, tail));
    };

    // certificates [0] present but signerInfos missing (read after [0] hits end).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(
        BuildPkcs7Buffer(wrapTail(DerExplicit0(DER_FILLER))), content));

    // certificates [0] and crls [1] present but signerInfos missing (read after [1] hits end).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(
        BuildPkcs7Buffer(wrapTail(DerExplicit0(DER_FILLER) + DerExplicit1(DER_FILLER))), content));

    // final tail object is not a SET (OCTET STRING instead).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(
        BuildPkcs7Buffer(wrapTail(DerOctetString(DER_FILLER))), content));

    // signerInfos SET is empty (length 0).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(
        BuildPkcs7Buffer(wrapTail(DerSet(""))), content));

    // trailing bytes after signerInfos SET (cursor does not reach SignedData end).
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(
        BuildPkcs7Buffer(wrapTail(BuildSignerInfosTail() + "X")), content));
}

/**
 * @tc.name: GetPkcs7ContentByAsn1_0600
 * @tc.desc: GetPkcs7ContentByAsn1 accepts optional certificates [0] and crls [1] tails.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPkcs7ContentByAsn1_0600, TestSize.Level1)
{
    const std::string profile = "{\"app\":\"demo\"}";
    std::string content;

    // certificates [0] then signerInfos.
    EXPECT_TRUE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(BuildContentInfo(
        BuildSignedData(profile, DerExplicit0(DER_FILLER) + BuildSignerInfosTail()))), content));
    EXPECT_EQ(content, profile);

    // crls [1] then signerInfos.
    EXPECT_TRUE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(BuildContentInfo(
        BuildSignedData(profile, DerExplicit1(DER_FILLER) + BuildSignerInfosTail()))), content));
    EXPECT_EQ(content, profile);

    // certificates [0] and crls [1] then signerInfos.
    EXPECT_TRUE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(BuildContentInfo(
        BuildSignedData(profile,
        DerExplicit0(DER_FILLER) + DerExplicit1(DER_FILLER) + BuildSignerInfosTail()))), content));
    EXPECT_EQ(content, profile);
}

/**
 * @tc.name: GetPkcs7ContentByAsn1_0700
 * @tc.desc: GetPkcs7ContentByAsn1 rejects indefinite-length BER and length-overflowing objects.
 * @tc.type: FUNC
 */
HWTEST_F(HapVerifyOpensslUtilsTest, GetPkcs7ContentByAsn1_0700, TestSize.Level1)
{
    std::string content;

    // indefinite-length constructed SEQUENCE (0x80 length + EOC) must be rejected: DER only.
    std::string indefinite = std::string("\x30\x80\x00\x00", 4);
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(indefinite), content));

    // outer SEQUENCE declares length 5 but only 1 content byte follows -> length overruns parent.
    std::string oversize = std::string("\x30\x05\x00", 3);
    EXPECT_FALSE(HapVerifyOpensslUtils::GetPkcs7ContentByAsn1(BuildPkcs7Buffer(oversize), content));
}
}
