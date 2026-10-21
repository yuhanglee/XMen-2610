/**
 * Copyright (C) 2008-2026 isoft Infrastructure Software Co., Ltd.
 * SPDX-License-Identifier: LGPL-2.1-only-with-exception
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation; version 2.1.
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License along with this library;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * or see <https://www.gnu.org/licenses/>.
 */
/*
 ************************************************************************************************************************
 **
 **  @file               : TcpIp_Algo.c
 **  @author             : xiankun.zhou
 **  @date               : 2025/6/12
 **  @vendor             : isoft
 **  @description        : algorithm implementations of TLS
 **
 ***********************************************************************************************************************/

/***********************************************************************************************************************
**                                          REVISION   HISTORY                                                        **
***********************************************************************************************************************/
/* <VERSION>    <DATE>       <AUTHOR>        <REVISION LOG>
 *  V2.2.0    [20250612]  [xiankun.zhou]   Implement basic algorithms.
 **********************************************************************************************************************/
/* PRQA S 2889 EOF */                   /* VL_QAC_MultiReturn */
/* PRQA S 3120, 3132 EOF */             /* VL_QAC_MagicNum */
/* PRQA S 2985 EOF */                   /* VL_TcpIp_2985 */
/* PRQA S 0686 EOF */                   /* VL_TcpIp_0686 */
/* PRQA S 0488 EOF */                   /* VL_TcpIp_0488 */
/* PRQA S 0499 EOF */                   /* VL_TcpIp_0499 */
/* PRQA S 4491, 4461, 4434, 4397 EOF */ /* VL_TcpIp_4491, VL_TcpIp_4461, VL_TcpIp_4434, VL_TcpIp_4397 */
/* PRQA S 2981, 2053 EOF */             /* VL_TcpIp_2981, VL_TcpIp_2053 */
/* PRQA S 3200 EOF */                   /* VL_TcpIp_3200 */
/* PRQA S 1258 EOF */                   /* VL_TcpIp_1258 */
/* PRQA S 3673, 3678 EOF */             /* VL_TcpIp_3200, VL_TcpIp_3678 */
/* PRQA S 0553 EOF */                   /* VL_QAC_UnUsedFiles */

#include "TcpIp_Cfg.h"

#if ((STD_ON == TCPIP_TCP_TLS_ENABLED) || (STD_ON == TCPIP_IPSEC_ENABLED))
#include "IStdLib.h"
#include "TcpIp_CfgTypes.h"
#include "Csm.h"

#if (STD_ON == TCPIP_TCP_TLS_ENABLED)
#include "TcpIp_Tls.h"
#endif

#if (STD_ON == TCPIP_IPSEC_ENABLED)
#include "TcpIp_Ike.h"
#include "TcpIp_Ike_Types.h"
#endif

/*******************************************************************************
**                      Global Variable Definitions                           **
*******************************************************************************/

/*******************************************************************************
**                      Private Function Declarations                         **
*******************************************************************************/
#if (STD_ON == TCPIP_TCP_TLS_ENABLED)
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_HKDFTFunc(
    tlsContext*  context,
    const uint8* PRK,
    uint32       PRKLen,
    const uint8* info,
    uint32       infoLen,
    uint8*       result,
    uint32       outputResultLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_HKDFExpand(
    tlsContext*  context,
    const uint8* PRK,
    uint32       PRKLen,
    const uint8* info,
    uint32       infoLen,
    uint8*       OKM,
    uint32       L);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_TlsPHash(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* seed,
    uint32       seedLen,
    uint8*       result,
    uint32       outputResultLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
/*******************************************************************************
**                      Private Functions                                     **
*******************************************************************************/

/***************************************************************
Inputs:
   PRK		a pseudorandom key of at least HashLen octets
            (usually, the output from the extract step)
   info 	optional context and application specific information
            (can be a zero-length string)
   L		length of output keying material in octets
            (<= 255*HashLen)
Output:
   OKM		output keying material (of L octets)

The output OKM is calculated as follows:

N = ceil(L/HashLen)
T = T(1) | T(2) | T(3) | ... | T(N)
OKM = first L octets of T

where:
T(0) = empty string (zero length)
T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
...
***************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_HKDFTFunc(
    tlsContext*  context,
    const uint8* PRK,
    uint32       PRKLen,
    const uint8* info,
    uint32       infoLen,
    uint8*       result,
    uint32       outputResultLen)
{
    Std_ReturnType ret            = E_OK;
    uint32         totalResultLen = 0u, TiLen = 128u, Timinus1Len = 0u, HMAC_hashIntputLen = 0u;
    uint8          Ti[128u] = {0u}, Timinus1[128u] = {0u}, HMAC_hashIntput[256u] = {0u};
    uint8*         resultPtr        = result;
    uint8          i                = 1u; /* T(0) = empty string (zero length) */
    uint32         macGenerateJobId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateJobId;
    uint32         macGenerateKeyId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateKeyId;

    ret = Csm_KeyElementSet(macGenerateKeyId, CRYPTO_KE_MAC_KEY, PRK, PRKLen);
    if (E_OK != ret)
    {
        return ret;
    }
    ret = Csm_KeySetValid(macGenerateKeyId);
    if (E_OK != ret)
    {
        return ret;
    }

    while (TRUE) /* PRQA S 2740,2870 */ /* VL_TcpIp_2740, VL_TcpIp_2870 */
    {
        /* T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x0i) */
        HMAC_hashIntputLen = 0u;
        (void)IStdLib_MemCpy(HMAC_hashIntput, Timinus1, Timinus1Len);
        HMAC_hashIntputLen += Timinus1Len; // PRQA S 2986 # while loop
        (void)IStdLib_MemCpy(&HMAC_hashIntput[HMAC_hashIntputLen], info, infoLen);
        HMAC_hashIntputLen += infoLen;
        (void)IStdLib_MemCpy(&HMAC_hashIntput[HMAC_hashIntputLen], &i, 1u);
        HMAC_hashIntputLen += 1u;

        ret = Csm_MacGenerate(
            macGenerateJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            HMAC_hashIntput,
            HMAC_hashIntputLen,
            Ti,
            &TiLen);
        if (E_OK != ret)
        {
            return ret;
        }
#if (TLS_USE_CSM_API != STD_ON) /* output length should be set by csm, but csm dosen't set now */
        TiLen = 32u;
#endif

        /* T = T(1) | T(2) | T(3) | ... | T(N) */
        if ((totalResultLen + TiLen) >= outputResultLen)
        {
            (void)IStdLib_MemCpy(resultPtr, Ti, outputResultLen - totalResultLen);
            break;
        }
        else
        {
            (void)IStdLib_MemCpy(resultPtr, Ti, TiLen);
            resultPtr += TiLen;
            totalResultLen += TiLen;
        }

        (void)IStdLib_MemCpy(Timinus1, Ti, TiLen);
        Timinus1Len = TiLen;

        i++;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/* HKDF-Expand(PRK, info, L) -> OKM */
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_HKDFExpand(
    tlsContext*  context,
    const uint8* PRK,
    uint32       PRKLen,
    const uint8* info,
    uint32       infoLen,
    uint8*       OKM,
    uint32       L)
{
    return TcpIp_HKDFTFunc(context, PRK, PRKLen, info, infoLen, OKM, L);
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/***************************************************************
RFC 5246 Sec 5.  HMAC and the Pseudorandom Function

P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    HMAC_hash(secret, A(2) + seed) +
    HMAC_hash(secret, A(3) + seed) + ...

  where + indicates concatenation.

  A() is defined as:

     A(0) = seed
     A(i) = HMAC_hash(secret, A(i-1))
***************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_TlsPHash(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* seed,
    uint32       seedLen,
    uint8*       result,
    uint32       outputResultLen)
{
    Std_ReturnType ret    = E_OK;
    uint32 totalResultLen = 0u, AiLen = 128u, Aiminus1Len = 128u, HMAC_hashIntputLen = 128u, HMAC_hashOutputLen = 128u;
    uint8  Ai[128u] = {0u}, Aiminus1[128u] = {0u};
    uint8  HMAC_hashIntput[256u] = {0u}, HMAC_hashOutput[128u] = {0u};
    uint8* resultPtr        = result;
    uint32 macGenerateJobId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateJobId;
    uint32 macGenerateKeyId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateKeyId;

    /* A(0) = seed */
    (void)IStdLib_MemCpy(Aiminus1, seed, seedLen);
    Aiminus1Len = seedLen;

    ret = Csm_KeyElementSet(macGenerateKeyId, CRYPTO_KE_MAC_KEY, secret, secretLen);
    if (E_OK != ret)
    {
        return ret;
    }
    ret = Csm_KeySetValid(macGenerateKeyId);
    if (E_OK != ret)
    {
        return ret;
    }

    while (TRUE) /* PRQA S 2740,2870 */ /* VL_TcpIp_2740, VL_TcpIp_2870 */
    {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        ret = Csm_MacGenerate(macGenerateJobId, CRYPTO_OPERATIONMODE_SINGLECALL, Aiminus1, Aiminus1Len, Ai, &AiLen);
        if (E_OK != ret)
        {
            return ret;
        }
#if (TLS_USE_CSM_API != STD_ON) /* output length should be set by csm, but csm dosen't set now */
        AiLen = 32u;
#endif

        (void)IStdLib_MemCpy(HMAC_hashIntput, Ai, AiLen);
        (void)IStdLib_MemCpy(&HMAC_hashIntput[AiLen], seed, seedLen);
        HMAC_hashIntputLen = AiLen + seedLen;

        ret = Csm_MacGenerate(
            macGenerateJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            HMAC_hashIntput,
            HMAC_hashIntputLen,
            HMAC_hashOutput,
            &HMAC_hashOutputLen);
        if (E_OK != ret)
        {
            return ret;
        }
#if (TLS_USE_CSM_API != STD_ON) /* output length should be set by csm, but csm dosen't set now */
        HMAC_hashOutputLen = 32u;
#endif

        if ((totalResultLen + HMAC_hashOutputLen) >= outputResultLen)
        {
            (void)IStdLib_MemCpy(resultPtr, HMAC_hashOutput, outputResultLen - totalResultLen);
            break;
        }
        else
        {
            (void)IStdLib_MemCpy(resultPtr, HMAC_hashOutput, HMAC_hashOutputLen);
            resultPtr += HMAC_hashOutputLen;
            totalResultLen += HMAC_hashOutputLen;
        }

        (void)IStdLib_MemCpy(Aiminus1, Ai, AiLen);
        Aiminus1Len = AiLen;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/*******************************************************************************
**						 Global Functions									  **
*******************************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_HKDFExtract(
    tlsContext*  context,
    const uint8* salt,
    uint32       saltLen,
    const uint8* IKM,
    uint32       IKMLen,
    uint8*       PRK,
    uint32*      PRKLenPtr)
{
    Std_ReturnType ret              = E_OK;
    uint32         macGenerateJobId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateJobId;
    uint32         macGenerateKeyId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateKeyId;

    ret = Csm_KeyElementSet(macGenerateKeyId, CRYPTO_KE_MAC_KEY, salt, saltLen);
    if (E_OK != ret)
    {
        return ret;
    }
    ret = Csm_KeySetValid(macGenerateKeyId);
    if (E_OK != ret)
    {
        return ret;
    }

    ret = Csm_MacGenerate(macGenerateJobId, CRYPTO_OPERATIONMODE_SINGLECALL, IKM, IKMLen, PRK, PRKLenPtr);
    if (E_OK != ret)
    {
        return ret;
    }
#if (TLS_USE_CSM_API != STD_ON) /* output length should be set by csm, but csm dosen't set now */
    *PRKLenPtr = 32u;
#endif
    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/***************************************************************
RFC 8446 Sec 7.1.	Key Schedule

HKDF-Expand-Label(Secret, Label, Context, Length) =
     HKDF-Expand(Secret, HkdfLabel, Length)

Where HkdfLabel is specified as:

struct {
    uint16 length = Length
    opaque label<7..255> = "tls13 " + Label
    opaque context<0..255> = Context
} HkdfLabel
***************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_HKDFExpandLabel(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* label,
    uint32       labelLen,
    const uint8* input,
    uint16       inputLen,
    uint8*       result,
    uint16       resultLen)
{
    uint8  HkdfLabel[64u] = {0u};
    uint8* HkdfLabelPtr   = HkdfLabel;
    uint32 strLen         = 0u;
    uint16 segLen         = 0u;

    strLen = CONST_STRLEN(TLS_LABEL_TLS13);

    /* uint16 length = Length */
    HkdfLabelPtr[0u] = (resultLen >> 8u) & 0xffu;
    HkdfLabelPtr[1u] = resultLen & 0xffu;
    HkdfLabelPtr += 2u;

    /* opaque label<7..255> = "tls13 " + Label */
    segLen           = strLen + labelLen;
    HkdfLabelPtr[0u] = segLen & 0xffu;
    HkdfLabelPtr++;
    (void)IStdLib_MemCpy(HkdfLabelPtr, TLS_LABEL_TLS13, strLen);
    HkdfLabelPtr += strLen;
    (void)IStdLib_MemCpy(HkdfLabelPtr, label, labelLen);
    HkdfLabelPtr += labelLen;

    /* opaque context<0..255> = Context */
    HkdfLabelPtr[0u] = inputLen & 0xffu;
    HkdfLabelPtr++;
    (void)IStdLib_MemCpy(HkdfLabelPtr, input, inputLen);
    HkdfLabelPtr += inputLen;

    return TcpIp_HKDFExpand(context, secret, secretLen, HkdfLabel, HkdfLabelPtr - HkdfLabel, result, resultLen);
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/***************************************************************
RFC 8446 Sec 7.1.	Key Schedule

Derive-Secret(Secret, Label, Messages) =
     HKDF-Expand-Label(Secret, Label,
                       Transcript-Hash(Messages), Hash.length)
***************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_DeriveSecret(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* label,
    uint32       labelLen,
    const uint8* messages,
    uint32       messagesLen,
    uint8*       result)
{
    Std_ReturnType ret                       = E_OK;
    uint32         msgHashLen                = TLS_HASH_MAX_LEN;
    uint8          msgHash[TLS_HASH_MAX_LEN] = {0u};
    uint32         hashJobId                 = context->handshakePtr->CsmHashVerifyJobId;

    ret = Csm_Hash(hashJobId, CRYPTO_OPERATIONMODE_SINGLECALL, messages, messagesLen, msgHash, &msgHashLen);
    if (E_OK != ret)
    {
        return ret;
    }
#if (TLS_USE_CSM_API != STD_ON) /* output length should be set by csm, but csm dosen't set now */
    msgHashLen = 32u;
#endif

    ret = TcpIp_HKDFExpandLabel(context, secret, secretLen, label, labelLen, msgHash, msgHashLen, result, 32u);
    if (E_OK != ret)
    {
        return ret;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/***************************************************************
RFC 5246 Sec 5.  HMAC and the Pseudorandom Function

PRF(secret, label, seed) = P_<hash>(secret, label + seed)
***************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_TlsPRF(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* label,
    uint32       labelLen,
    const uint8* seed,
    uint32       seedLen,
    uint8*       result,
    uint32       resultLen)
{
    Std_ReturnType ret             = E_OK;
    uint8          PHashSeed[256u] = {0u};
    uint32         PHashSeedLen    = labelLen + seedLen;

    if (PHashSeedLen > 256u)
    {
        return E_NOT_OK;
    }

    (void)IStdLib_MemCpy(PHashSeed, label, labelLen);
    (void)IStdLib_MemCpy(&PHashSeed[labelLen], seed, seedLen);

    ret = TcpIp_TlsPHash(context, secret, secretLen, PHashSeed, PHashSeedLen, result, resultLen);

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#endif

#if (STD_ON == TCPIP_IPSEC_ENABLED)
/*The PRF+ defined in RFC7296 limits the number of PRF iterations to no more than 255*/
#define PRF_LIMITS 0xFF

/*Macros for Numeric Constants*/
#define CONST_1 1

/* Configuration locally*/
#define HMAC_MAXLEN       64
#define IPSEC_SEED_MAXLEN 256
#define IPSEC_KEY_MAXLEN  256

#define TCPIP_START_SEC_CONFIG_DATA_UNSPECIFIED
#include "TcpIp_MemMap.h"
extern const IKE_ConfigType IKE_Config;
#define TCPIP_STOP_SEC_CONFIG_DATA_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * Implements the PRF+ function as specified in RFC 7296 for IPSec.
 * This function generates a variable-length pseudorandom output by iteratively applying PRF.
 */
Std_ReturnType Ipsec_PrfPlus(
    uint32       jobId,
    uint32       keyId,
    const uint8* keyPtr,
    uint32       keyLen,
    const uint8* seed,
    uint32       seed_len,
    uint8*       output,
    uint32       output_len)
{
    uint8          temp[HMAC_MAXLEN]                                 = {0};
    uint8          prev[HMAC_MAXLEN]                                 = {0};
    uint8          buffer[HMAC_MAXLEN + IPSEC_SEED_MAXLEN + CONST_1] = {0};
    uint32         PrfLen                                            = HMAC_MAXLEN;
    uint32         copied                                            = 0;
    uint32         counter                                           = CONST_1;
    Std_ReturnType Std_Return                                        = E_OK;

    (void)Csm_KeyElementSet(keyId, CRYPTO_KE_CIPHER_KEY, keyPtr, keyLen);
    (void)Csm_KeySetValid(keyId);

    while (copied < output_len)
    {
        if (counter == CONST_1)
        {
            /*T1 = prf(K, S | 0x01)*/
            IStdLib_MemCpy(buffer, seed, seed_len);
            buffer[seed_len] = counter;

            Std_Return =
                Csm_MacGenerate(jobId, CRYPTO_OPERATIONMODE_SINGLECALL, buffer, seed_len + CONST_1, temp, &PrfLen);
            if (Std_Return != E_OK)
            {
                return Std_Return;
            }
        }
        else
        {
            /*Tn = prf(K, Tn-1 | S | 0xXX)*/
            IStdLib_MemCpy(buffer, prev, keyLen);
            IStdLib_MemCpy(buffer + keyLen, seed, seed_len);
            buffer[keyLen + seed_len] = counter;

            Std_Return = Csm_MacGenerate(
                jobId,
                CRYPTO_OPERATIONMODE_SINGLECALL,
                buffer,
                keyLen + seed_len + CONST_1,
                temp,
                &PrfLen);
            if (Std_Return != E_OK)
            {
                return Std_Return;
            }
        }

        uint32 to_copy = (output_len - copied) > PrfLen ? PrfLen : (output_len - copied);
        IStdLib_MemCpy(output + copied, temp, to_copy);
        copied += to_copy;
        IStdLib_MemCpy(prev, temp, PrfLen);
        counter++;

        /*RFC7296 stipulates The prf+ function is not defined beyond 255 times the size of*/
        /*the prf function output*/
        if (counter > PRF_LIMITS)
        {
            break;
        }
    }
    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * Generates all required security association (SA) keys for IPSec using PRF and PRF+ functions.
 * This function follows RFC 7296 to generate SKEYSEED and derive all necessary keys for an IPSec SA.
 */
Std_ReturnType Ipsec_IkeSaKeysGenerate(IkeConnContext* context)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint32         PrfoutLen  = context->PrfKeyLen;
    uint32         Sa_KeysLen;
    uint32         prfJobId = IKE_Config.Transforms->PrfTransform[context->PrfTransformPbCfgId].JobId;
    uint32         prfKeyId = IKE_Config.Transforms->PrfTransform[context->PrfTransformPbCfgId].KeyId;

    /*SKEYSEED = prf(Ni | Nr, g^ir)*/
    Std_Return = Csm_KeyElementSet(prfKeyId, CRYPTO_KE_CIPHER_KEY, context->InitiatorNonce, IKE_NONCE_LEN << 1);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    (void)Csm_KeySetValid(prfKeyId);
    Std_Return = Csm_MacGenerate(
        prfJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        context->DHKey,
        context->DHKeyLen,
        context->SKEYSEED,
        &PrfoutLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    Sa_KeysLen = context->PrfKeyLen * 3 + context->IntegKeyLen * 2 + context->EncrKeyLen * 2;

    /*Calculate prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)*/
    uint8  seed[IPSEC_SEED_MAXLEN];
    uint32 seed_len = 0;

    IStdLib_MemCpy(seed, context->InitiatorNonce, IKE_NONCE_LEN << 1);
    seed_len += (IKE_NONCE_LEN << 1);
    IStdLib_MemCpy(seed + seed_len, context->InitiatorSPI, IKE_IKE_SPI_LEN << 1);
    seed_len += (IKE_IKE_SPI_LEN << 1);

    uint8 keys[IPSEC_KEY_MAXLEN];
    Std_Return = Ipsec_PrfPlus(prfJobId, prfKeyId, context->SKEYSEED, PrfoutLen, seed, seed_len, keys, Sa_KeysLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /*Allocate key material*/
    /*RFC7296 indicating that the quantities SK_d, SK_ai, SK_ar, SK_ei, SK_er*/
    /*SK_pi, and SK_pr are taken in order from the generated bits of the prf+*/
    uint8* keyPtr = keys;

    IStdLib_MemCpy(context->SK_d, keyPtr, context->PrfKeyLen);
    keyPtr += context->PrfKeyLen;

    IStdLib_MemCpy(context->SK_ai, keyPtr, context->IntegKeyLen);
    keyPtr += context->IntegKeyLen;

    IStdLib_MemCpy(context->SK_ar, keyPtr, context->IntegKeyLen);
    keyPtr += context->IntegKeyLen;

    IStdLib_MemCpy(context->SK_ei, keyPtr, context->EncrKeyLen);
    keyPtr += context->EncrKeyLen;

    IStdLib_MemCpy(context->SK_er, keyPtr, context->EncrKeyLen);
    keyPtr += context->EncrKeyLen;

    IStdLib_MemCpy(context->SK_pi, keyPtr, context->PrfKeyLen);
    keyPtr += context->PrfKeyLen;

    IStdLib_MemCpy(context->SK_pr, keyPtr, context->PrfKeyLen);

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType Ipsec_ChildSaKeysGenerate(IkeConnContext* context, TcpIp_IpSecSAType* childSA)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint32         Sa_KeysLen;
    uint32         prfJobId = IKE_Config.Transforms->PrfTransform[context->PrfTransformPbCfgId].JobId;
    uint32         prfKeyId = IKE_Config.Transforms->PrfTransform[context->PrfTransformPbCfgId].KeyId;

    Sa_KeysLen = childSA->IntegKeyLen * 2;

    /*Calculate prf+(SK_d, Ni | Nr)*/
    uint8 seed[IPSEC_SEED_MAXLEN];

    uint8* seedPtr = seed;
    IStdLib_MemCpy(seedPtr, context->InitiatorNonce, IKE_NONCE_LEN);
    seedPtr += IKE_NONCE_LEN;

    IStdLib_MemCpy(seedPtr, context->ResponderNonce, IKE_NONCE_LEN);
    seedPtr += IKE_NONCE_LEN;

    uint8  keys[IPSEC_KEY_MAXLEN];
    uint32 seed_len = seedPtr - seed;
    Std_Return = Ipsec_PrfPlus(prfJobId, prfKeyId, context->SK_d, context->PrfKeyLen, seed, seed_len, keys, Sa_KeysLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    uint8* keyPtr = keys;

    IStdLib_MemCpy(childSA->IKi, keyPtr, childSA->IntegKeyLen);
    keyPtr += childSA->IntegKeyLen;

    IStdLib_MemCpy(childSA->IKr, keyPtr, childSA->IntegKeyLen);

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#endif

#endif /* (STD_ON == TCPIP_TCP_TLS_ENABLED) || (STD_ON == TCPIP_IPSEC_ENABLED) */
