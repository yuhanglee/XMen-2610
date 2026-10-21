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
 **  @file               : TcpIp_TlsGeneral.c
 **  @author             : pengfei.zhu
 **  @date               :
 **  @vendor             : isoft
 **  @description        : TLS general API implementations
 **
 ***********************************************************************************************************************/

/*******************************************************************************
**                      REVISION   HISTORY                                    **
*******************************************************************************/
/* <VERSION>    <DATE>       <AUTHOR>        <REVISION LOG>
 *  V2.0.0    [20200828]  [pengfei.zhu]   Add Tcp_Tls function.
 *  V2.0.1    [20200928]  [pengfei.zhu]   QAC test.
 *  V2.2.0    [20250612]  [xiankun.zhou]  Code refactoring
 ******************************************************************************/
/* PRQA S 2889 EOF */       /* VL_QAC_MultiReturn */
/* PRQA S 3120, 3132 EOF */ /* VL_QAC_MagicNum */
/* PRQA S 2982 EOF */       /* VL_TcpIp_2982 */
/* PRQA S 2985 EOF */       /* VL_TcpIp_2985 */
/* PRQA S 3556 EOF */       /* VL_TcpIp_3556 */
/* PRQA S 0488, 0317 EOF */ /* VL_TcpIp_0488, VL_TcpIp_0317 */
/* PRQA S 0686 EOF */       /* VL_TcpIp_0686 */
/* PRQA S 0432, 0499 EOF */ /* VL_TcpIp_0432, VL_TcpIp_0499 */
/* PRQA S 1338 EOF */       /* VL_TcpIp_1338 */
/* PRQA S 1277 EOF */       /* VL_TcpIp_1277 */
/* PRQA S 1258 EOF */       /* VL_TcpIp_1258 */
/* PRQA S 4491 EOF */       /* VL_TcpIp_4491 */
/* PRQA S 4461 EOF */       /* VL_TcpIp_4461 */
/* PRQA S 4434 EOF */       /* VL_TcpIp_4434 */
/* PRQA S 4397 EOF */       /* VL_TcpIp_4397 */
/* PRQA S 4115, 3344 EOF */ /* VL_TcpIp_4115, VL_TcpIp_3344 */
/* PRQA S 2981, 2053 EOF */ /* VL_TcpIp_2981, VL_TcpIp_2053 */
/* PRQA S 3200 EOF */       /* VL_TcpIp_3200 */
/* PRQA S 3673, 3678 EOF */ /* VL_TcpIp_3673, VL_TcpIp_3678 */
/* PRQA S 0553 EOF */       /* VL_QAC_UnUsedFiles */
/* PRQA S 6520 EOF */       /* VL_MTR_TcpIp_STVAR */

#include "TcpIp_Cfg.h"

#if (TCPIP_TCP_TLS_ENABLED == STD_ON)
#include "TcpIp_Tls.h"
#include "lwip/mem.h"
#include "Csm.h"
#include <string.h>

/*******************************************************************************
**                      Global Variable Definitions                           **
*******************************************************************************/
#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Handshake worker busy flags (extern reference).
 * @range None
 */
extern boolean TcpIp_TlsHandshakeBusyStatus[TCPIP_TLS_HANDSHAKE_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Ciphersuite worker busy flags (extern reference).
 * @range None
 */
extern boolean TcpIp_TlsCiphersuiteBusyStatus[TCPIP_TLS_CIPHERSUITE_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_PTR
#include "TcpIp_MemMap.h"
/**
 * @brief Global TLS configuration pointer (extern reference).
 * @range None
 */
extern const TcpIp_TlsConfigType* TcpIp_TlsCfgPtr;
#define TCPIP_STOP_SEC_VAR_CLEARED_PTR
#include "TcpIp_MemMap.h"

/*******************************************************************************
**                      Private Function Declarations                         **
*******************************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Select handshake ref from configuration(PBcfg.c).
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		TLS error number
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 */
TCPIP_LOCAL sint32 TcpIp_TlsHandshakeSelect(tlsContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse supported version extension.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
                parsePtr: pointer to data.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseSupportedVersionExt(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* parsePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse key share extension.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
                parsePtr: pointer to data.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 *  key exchange of TLS 1.3 is in key share extension
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseKeyShareExt(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* parsePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Build Certificate Body.
 * @param[in]    context   : TLS context pointer.
 *               certificateDataPtr   : certificate data pointer.
 * @return       -
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL void TcpIp_TlsBuildCertificateBody(tlsContext* context, KeyM_CertDataType* certificateDataPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Build and send TLS 1.3 Handshake Finished packet.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_Tls13WriteHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Read TLS record header from pbuf and set input state pointers.
 *
 * @param[in] tlsSocketPtr TLS socket pointer.
 * @return Bytes read on success; 0 if need more; negative TLS error code.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsGetRecordHdr(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Build and send TLS 1.3 Handshake Finished packet.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_Tls12WriteHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/*******************************************************************************
**                      Private Functions                                     **
*******************************************************************************/

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_Xor(uint32 len, const uint8* a1, const uint8* a2, uint8* des)
{
    uint32 i;
    for (i = 0u; i < len; i++)
    {
        des[i] = a1[i] ^ a2[i];
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsHandshakeSelect(tlsContext* context)
{
    uint8        handshakeNum = context->ciphersuiteWorkerPtr->HandshakeNum, handshakeId = 0u;
    const uint8* handshakeIdPtr = context->ciphersuiteWorkerPtr->HandshakeIdList;

    for (uint32 i = 0u; i < handshakeNum; i++)
    {
        handshakeId = handshakeIdPtr[i];
        if (FALSE == TcpIp_TlsHandshakeBusyStatus[handshakeId])
        {
            context->handshakePtr                     = &TcpIp_TlsCfgPtr->HandshakePtr[handshakeId];
            context->handshakeId                      = handshakeId;
            TcpIp_TlsHandshakeBusyStatus[handshakeId] = TRUE;
            return TLS_RETURN_OK;
        }
    }

    return TLS_ERR_INTERNAL_ERROR;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Select and reserve a ciphersuite from configuration by ID.
 *
 * Marks the chosen ciphersuite as busy, sets related context fields
 * (key sizes, IV sizes, hash length, TLS version), and binds the
 * corresponding worker/handshake descriptors.
 *
 * @param[in,out] context           TLS context.
 * @param[in]     chCiphersuiteId   Ciphersuite ID from peer's list.
 * @return TLS_RETURN_OK on success; TLS_ERR_NO_USABLE_CIPHERSUITE or error.
 */
sint32 TcpIp_TlsCiphersuiteSelectInner(tlsContext* context, uint16 chCiphersuiteId)
{
    sint32                                          ret              = TLS_RETURN_OK;
    const uint8*                                    ciphersuiteIdPtr = context->connectionConfigPtr->CiphersuiteIdList;
    const TcpIp_TlsCiphersuiteDefinitionConfigType* ciphersuitePtr   = NULL_PTR;
    uint8 ciphersuiteNum = context->connectionConfigPtr->CiphersuiteNum, ciphersuiteListId = 0u;

    for (uint32 i = 0u; i < ciphersuiteNum; i++)
    {
        ciphersuiteListId = ciphersuiteIdPtr[i];
        ciphersuitePtr    = &TcpIp_TlsCfgPtr->CiphersuiteDefinitionPtr[ciphersuiteListId];
        /* busy ciphersuite is not available */
        if ((chCiphersuiteId == ciphersuitePtr->CiphersuiteId)
            && (FALSE == TcpIp_TlsCiphersuiteBusyStatus[ciphersuiteListId]))
        {
            /* search available ciphersuite, set imfo according to ciphersuite */
            switch (chCiphersuiteId)
            {
            case TLS_RSA_WITH_AES_128_CBC_SHA256:
                context->KeyExchange       = TLS_KEY_EXCHANGE_RSA;
                context->record_IV_length  = 16u;
                context->write_key_len     = 16u;
                context->write_MAC_key_len = 32u;
                context->write_IV_len      = 0u;
                context->hashLen           = 32u;
                context->minorVersion      = TLS_MINOR_VERSION_3;
                break;

            case TLS_RSA_WITH_AES_256_CBC_SHA256:
                context->KeyExchange       = TLS_KEY_EXCHANGE_RSA;
                context->record_IV_length  = 32u;
                context->write_key_len     = 32u;
                context->write_MAC_key_len = 32u;
                context->write_IV_len      = 0u;
                context->hashLen           = 32u;
                context->minorVersion      = TLS_MINOR_VERSION_3;
                break;

            case TLS_AES_128_GCM_SHA256:
                context->KeyExchange       = TLS_KEY_EXCHANGE_ECDHE;
                context->record_IV_length  = 16u;
                context->write_key_len     = 16u;
                context->write_MAC_key_len = 32u;
                context->write_IV_len      = 12u;
                context->hashLen           = 32u;
                context->minorVersion      = TLS_MINOR_VERSION_4;
                break;

            case TLS_AES_256_GCM_SHA384:
                context->KeyExchange       = TLS_KEY_EXCHANGE_ECDHE;
                context->record_IV_length  = 16u;
                context->write_key_len     = 16u;
                context->write_MAC_key_len = 32u;
                context->write_IV_len      = 12u;
                context->hashLen           = 48u;
                context->minorVersion      = TLS_MINOR_VERSION_4;
                break;

            default: /* PRQA S 2016 */ /* VL_QAC_EmptyClause */
                break;
            }

            context->ciphersuiteDefinitionPtr = ciphersuitePtr;
            /* Worker and Ciphersuite one-to-one corresponding relations, whilch measn they have same index */
            context->ciphersuiteWorkerPtr = &TcpIp_TlsCfgPtr->CiphersuiteWorkerPtr[ciphersuiteListId];
            context->ciphersuiteId        = ciphersuiteListId;
            /* set ciphersuite status to busy */
            TcpIp_TlsCiphersuiteBusyStatus[ciphersuiteListId] = TRUE;

            /* TLS 1.3 client doesn't need to search handshake ref */
            if ((TLS_MINOR_VERSION_4 != context->minorVersion)
                || (TLS_CLIENT != context->connectionConfigPtr->ConnectionType))
            {
                ret = TcpIp_TlsHandshakeSelect(context);
            }

            return ret;
        }
    }

    return TLS_ERR_NO_USABLE_CIPHERSUITE;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Select ciphersuite ref from configuration(PBcfg.c).
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		TLS error number
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 */
sint32 TcpIp_TlsCiphersuiteSelect(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** parsePtr)
{
    sint32      ret            = TLS_RETURN_OK;
    tlsContext* context        = &tlsSocketPtr->socketTlsContext;
    uint16      ciphersuiteLen = 0u, chCiphersuiteId = 0u;
    uint8 *     ciphersuiteLenPtr = NULL_PTR, *ciphersuitePtr = NULL_PTR;

    ciphersuiteLenPtr = *parsePtr;
    ciphersuiteLen    = (ciphersuiteLenPtr[0u] << 8u) | ciphersuiteLenPtr[1u];
    if (0u == ciphersuiteLen)
    {
        return TLS_ERR_NO_USABLE_CIPHERSUITE;
    }
    (*parsePtr) += 2u;

    ciphersuitePtr = *parsePtr;

    for (uint32 i = 0u; i < ciphersuiteLen; i += 2u)
    {
        chCiphersuiteId = (ciphersuitePtr[i] << 8u) | ciphersuitePtr[1u + i];
        ret             = TcpIp_TlsCiphersuiteSelectInner(context, chCiphersuiteId);
        if (TLS_RETURN_OK == ret)
        {
            (*parsePtr) += ciphersuiteLen;
            return TLS_RETURN_OK;
        }
    }

    return TLS_ERR_NO_USABLE_CIPHERSUITE;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsGetRecordHdr(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    tlsContext* context = &tlsSocketPtr->socketTlsContext;

    context->inBufPtr = context->inPBuf->payload;
    uint16 readLen    = TcpIp_TlsBioRecvCallBack(tlsSocketPtr, context->inBufPtr, TLS_RECORD_HEADER_LENGTH);
    if (0u == readLen)
    {
        return TLS_ERR_NET_BAD_INPUT_DATA;
    }

    context->inRecordContentType   = context->inRecordHdrStart[0u];
    context->inRecordContentLength = (context->inRecordHdrStart[3u] << 8u) | context->inRecordHdrStart[4u];
    context->inBufPtr += readLen;
    context->inRemainingLen   = context->inRecordContentLength;
    context->inRecordHdrStart = context->inPBuf->payload;

    if (context->inRecordContentLength > TLS_IN_PAYLOAD_LEN)
    {
        return TLS_ERR_NET_BUFFER_TOO_SMALL;
    }

    return readLen;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsGetNextRecord(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret     = TLS_RETURN_OK;
    tlsContext* context = &tlsSocketPtr->socketTlsContext;

    /* Read record header, inRemainingLen==0 means previous record has been fully read */
    if (0u == context->inRemainingLen)
    {
        ret = TcpIp_TlsGetRecordHdr(tlsSocketPtr);
        if (0 == ret)
        {
            return TLS_ERR_NET_BAD_INPUT_DATA;
        }
    }

    uint16 readLen = TcpIp_TlsBioRecvCallBack(tlsSocketPtr, context->inBufPtr, context->inRemainingLen);
    if (0u == readLen)
    {
        return TLS_ERR_NET_BAD_INPUT_DATA;
    }

    context->inBufPtr += readLen;
    context->inRemainingLen -= (uint16)readLen;

    if (context->inRemainingLen)
    {
        /* wait for next receive callback */
        return TLS_ERR_SSL_WANT_READ;
    }

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_TlsBuildRecordHeader(tlsContext* context)
{
    uint8* recordHeaderPtr = context->outRecordHdrStart;
    uint16 lengthFied      = 0u;

    context->outTotalLen = context->outRecordContentLength + TLS_RECORD_HEADER_LENGTH;

    recordHeaderPtr[0u] = context->outRecordContentType;
    recordHeaderPtr[1u] = TLS_MAJOR_VERSION_3;
    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        recordHeaderPtr[2u] = TLS_MINOR_VERSION_3;
    }
    else
    {
        recordHeaderPtr[2u] = context->minorVersion;
    }

    lengthFied          = context->outRecordContentLength;
    recordHeaderPtr[3u] = (lengthFied >> 8u) & 0xffu;
    recordHeaderPtr[4u] = lengthFied & 0xffu;

    context->seqNum++;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_TlsGenerateRandomNumber(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    uint32                                    currentTimeUtc = 0u, randomLen = TLS_RANDOM_LENGTH;
    Std_ReturnType                            Std_Return    = E_NOT_OK;
    const TcpIp_TlsConnectionConfigType*      connectionPtr = tlsSocketPtr->socketTlsContext.connectionConfigPtr;
    const TcpIp_Up_TlsGetCurrentTimeStampType getCurrentTimeStampFuncPtr = connectionPtr->ConnectionGetTimeFunc;
    uint8*                                    randResultPtr              = NULL;

    if (TLS_CLIENT == connectionPtr->ConnectionType)
    {
        randResultPtr = tlsSocketPtr->socketTlsContext.clientRandom;
    }
    else
    {
        randResultPtr = tlsSocketPtr->socketTlsContext.serverRandom;
    }

    Std_Return = TcpIp_TlsCsmRandomGenerate(randResultPtr, &randomLen);
    if ((E_OK == Std_Return) && getCurrentTimeStampFuncPtr)
    {
        Std_Return = getCurrentTimeStampFuncPtr(&currentTimeUtc);
        if (E_OK == Std_Return)
        {
            randResultPtr[0u] = (currentTimeUtc >> 24u) & 0xffu;
            randResultPtr[1u] = (currentTimeUtc >> 16u) & 0xffu;
            randResultPtr[2u] = (currentTimeUtc >> 8u) & 0xffu;
            randResultPtr[3u] = currentTimeUtc & 0xffu;
        }
    }

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_TlsUpdateHSHash(tlsContext* context)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint32         hashJobId  = context->handshakePtr->CsmHashVerifyJobId;
    uint32         resultLen  = 0u;
    Std_Return                = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_UPDATE,
        context->outRecordContentStart,
        context->outRecordContentLength,
        context->handshakeMsgHash,
        &resultLen);

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsHandshakeStart(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32 ret = TLS_RETURN_OK;

    /* TLS state machine loop */
    while (tlsSocketPtr->socketTlsContext.state != TLS_HANDSHAKE_DONE)
    {
        if (TLS_CLIENT == tlsSocketPtr->socketTlsContext.connectionConfigPtr->ConnectionType)
        {
            ret = TcpIp_TlsClientHandshakeStep(tlsSocketPtr);
        }
        else
        {
            ret = TcpIp_TlsServerHandshakeStep(tlsSocketPtr);
        }

        if (ret != TLS_RETURN_OK)
        {
            break;
        }
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsParseCertificate(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32            ret                   = TLS_RETURN_OK;
    Std_ReturnType    Std_Return            = E_NOT_OK;
    uint8*            parsePtr              = NULL;
    tlsContext*       context               = &tlsSocketPtr->socketTlsContext;
    KeyM_CertDataType certData              = {.certData = NULL_PTR, .certDataLength = 0u};
    uint8             certificateIdentityId = context->connectionConfigPtr->CertificateIdentityIdList[0u];
    uint16 certId   = TcpIp_TlsCfgPtr->CertificateIdentityPtr[certificateIdentityId].CipherKeyMRemoteCertificateId,
           certsLen = 0u;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        ret = TcpIp_Tls13Decrypt(context);
        if (TLS_RETURN_OK != ret)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        /* TLS_SERVER_CERTIFICATE -> TLS_CERTIFICATE_VERIFY */
        context->state = TLS_CERTIFICATE_VERIFY;
    }
    else
    {
        /* TLS_SERVER_CERTIFICATE -> TLS_SERVER_HELLO */
        context->state = TLS_SERVER_HELLO_DONE;
        if (TLS_MSG_TYPE_HANDSHAKE != context->inRecordContentType)
        {
            return TLS_ERR_UNEXPECTED_MESSAGE;
        }
    }

    parsePtr = context->inRecordContentStart;

    /* handshake type check */
    if (TLS_HS_TYPE_CERTIFICATE != parsePtr[0u])
    {
        return TLS_ERR_BAD_HS_CLIENT_HELLO;
    }
    parsePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /* certificate request context length */
        parsePtr++;
    }

    /* todo: certificate chain verify */
    certsLen = (parsePtr[0u] << 16u) | (parsePtr[1u] << 8u) | parsePtr[2u];
    parsePtr += 3u;
    TCPIP_UNUSED_ARG(certsLen);

    certData.certDataLength = (parsePtr[0u] << 16u) | (parsePtr[1u] << 8u) | parsePtr[2u];
    if (0u == certData.certDataLength)
    {
        return TLS_ERR_BAD_HS_CERTIFICATE;
    }
    parsePtr += 3u;

    /* verify certificate */
    certData.certData = parsePtr;
    Std_Return        = KeyM_SetCertificate(certId, &certData);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_BAD_HS_CERTIFICATE;
    }

#if (TLS_USE_CSM_API == STD_ON)
    Std_Return = KeyM_VerifyCertificate(certId);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_BAD_HS_CERTIFICATE;
    }

    Std_Return = TcpIp_TlsUpdateHSHash(context);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
#else
    (void)IStdLib_MemCpy(
        &context->handshake_messages[context->handshake_messagesLen],
        context->inRecordContentStart,
        context->inRecordContentLength);
    context->handshake_messagesLen += context->inRecordContentLength;
#endif

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsVersionCheck(tlsContext* context)
{
    uint8 majorVersion = 0u;
    uint8 minorVersion = 0u;

    /* record header version check */
    majorVersion = context->inRecordHdrStart[1u];
    if (majorVersion < TLS_MIN_MAJOR_VERSION)
    {
        return TLS_ERR_BAD_HS_PROTOCOL_VERSION;
    }

    /* content version check */
    majorVersion = context->inRecordContentStart[4u];
    minorVersion = context->inRecordContentStart[5u];
    if ((majorVersion < TLS_MIN_MAJOR_VERSION) || (minorVersion < TLS_MIN_MINOR_VERSION))
    {
        return TLS_ERR_BAD_HS_PROTOCOL_VERSION;
    }

    context->minorVersion = minorVersion;

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#if (STD_ON == TCPIP_TLS_SERVER_NAME_INDICATION)
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Parse Server Name Indication (SNI) extension and bind matching certificate identity.
 *
 * @param[in,out] tlsSocketPtr TLS socket pointer.
 * @param[in]     parsePtr     Pointer into extensions buffer at SNI payload.
 * @return TLS_RETURN_OK on success; TLS_ERR_NET_UNKNOWN_HOST if no identity matches.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseServerNameExt(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* parsePtr)
{
    uint8* certificateIdentityIdPtr = tlsSocketPtr->socketTlsContext.connectionConfigPtr->CertificateIdentityIdList;
    TcpIp_TlsCertificateIdentityConfigType* certificateIdentityPtr = NULL_PTR;
    uint8  certNum = tlsSocketPtr->socketTlsContext.connectionConfigPtr->CertificateIdentityNum;
    uint8* namePtr = NULL_PTR;

    uint16 nameLen = (parsePtr[3u] << 8u) | parsePtr[4u];
    namePtr        = parsePtr + 5u;

    for (uint32 i = 0u; i < certNum; i++)
    {
        certificateIdentityPtr = &TcpIp_TlsCfgPtr->CertificateIdentityPtr[certificateIdentityIdPtr[i]];
        if (0u == IStdLib_MemCmp(namePtr, certificateIdentityPtr->ServerNameIdentification, nameLen))
        {
            tlsSocketPtr->socketTlsContext.certificateIdentityPtr = certificateIdentityPtr;
            return TLS_RETURN_OK;
        }
    }

    return TLS_ERR_NET_UNKNOWN_HOST;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#endif /* TCPIP_TLS_SERVER_NAME_INDICATION */

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseSupportedVersionExt(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* parsePtr)
{
    uint8  versionLen = 0u, minorVersion = tlsSocketPtr->socketTlsContext.minorVersion;
    uint8* versionPtr = NULL_PTR;

    if (TLS_CLIENT == tlsSocketPtr->socketTlsContext.connectionConfigPtr->ConnectionType)
    {
        /* client only check if server's supported version is same as ciphersuite selected */
        versionPtr = parsePtr;
        if ((TLS_MAJOR_VERSION_3 == versionPtr[0u]) && (minorVersion == versionPtr[1u]))
        {
            return TLS_RETURN_OK;
        }
    }
    else
    {
        /* server check if server's version is in support list */
        versionLen = parsePtr[0u];
        versionPtr = &parsePtr[1u];

        while (versionLen)
        {
            if ((TLS_MAJOR_VERSION_3 == versionPtr[0u]) && (minorVersion == versionPtr[1u]))
            {
                return TLS_RETURN_OK;
            }
            versionLen -= 2u;
            versionPtr += 2u;
        }
    }

    return TLS_ERR_BAD_HS_PROTOCOL_VERSION;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseKeyShareExt(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* parsePtr)
{
    Std_ReturnType Std_Return  = E_NOT_OK;
    tlsContext*    context     = &tlsSocketPtr->socketTlsContext;
    uint16         keyShareLen = 0u, keyShareGroup = 0u;
    uint32         keyExchangeLen = 0u;

    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        /* client check if server's group is in its own support list */
        keyShareGroup = (parsePtr[0u] << 8u) | parsePtr[1u];
        parsePtr += 2u;

        keyExchangeLen = (parsePtr[0u] << 8u) | parsePtr[1u];
        parsePtr += 2u;

        /*  now only support ECDHE_GROUP_X25519 */
        if (ECDHE_GROUP_X25519 == keyShareGroup)
        {
            uint8 peerPubKey[TLS_DH_KEY_MAX_LEN] = {0u};
            uint8 resultKey[TLS_DH_KEY_MAX_LEN]  = {0u};
            (void)IStdLib_MemCpy(peerPubKey, parsePtr, keyExchangeLen);
            uint32 exchangeKeyId = context->handshakePtr->CsmKeyExchangeKeyId;
            Std_Return           = Csm_KeySetValid(exchangeKeyId);
            if (E_OK != Std_Return)
            {
                return TLS_ERR_INTERNAL_ERROR;
            }

            /* caculate shared key */
            Std_Return = Csm_KeyExchangeCalcSecret(exchangeKeyId, peerPubKey, keyExchangeLen);
            if (E_OK != Std_Return)
            {
                return TLS_ERR_INTERNAL_ERROR;
            }

            Std_Return = Csm_KeySetValid(exchangeKeyId);
            if (E_OK != Std_Return)
            {
                return TLS_ERR_INTERNAL_ERROR;
            }

            /* get shared key */
            Std_Return =
                Csm_KeyElementGet(exchangeKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, resultKey, &keyExchangeLen);
            if (E_OK != Std_Return)
            {
                return TLS_ERR_INTERNAL_ERROR;
            }

            (void)IStdLib_MemCpy(context->ECDHEKey, resultKey, keyExchangeLen);
            return TLS_RETURN_OK;
        }
    }
    else
    {
        /* server choose one from provided groups */
        keyShareLen = (parsePtr[0u] << 8u) | parsePtr[1u];
        parsePtr += 2u;

        while (keyShareLen)
        {
            keyShareGroup = (parsePtr[0u] << 8u) | parsePtr[1u];
            parsePtr += 2u;
            keyShareLen -= 2u;

            keyExchangeLen = (parsePtr[0u] << 8u) | parsePtr[1u];
            parsePtr += 2u;
            keyShareLen -= 2u;

            /* only ECDHE_GROUP_X25519 supprted now */
            if (ECDHE_GROUP_X25519 == keyShareGroup)
            {
                (void)IStdLib_MemCpy(context->ECDHEKey, parsePtr, keyExchangeLen);
                context->DHKeyLen = TLS_X25519_KEY_LEN;
                return TLS_RETURN_OK;
            }

            keyShareLen -= keyExchangeLen;
        }
    }

    return TLS_ERR_NO_USABLE_CIPHERSUITE;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsParseExtensions(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* parsePtr)
{
    sint32 ret    = TLS_RETURN_OK;
    uint16 extLen = 0u, extInnerLen = 0u, type = 0u;

    extLen = (parsePtr[0u] << 8u) | parsePtr[1u];
    parsePtr += 2u;

    while (extLen)
    {
        type        = (parsePtr[0u] << 8u) | parsePtr[1u];
        extInnerLen = (parsePtr[2u] << 8u) | parsePtr[3u];
        parsePtr += 4u;

        switch (type)
        {
#if (STD_ON == TCPIP_TLS_SERVER_NAME_INDICATION)
        case TLS_EXT_SERVERNAME:
            ret = TcpIp_TlsParseServerNameExt(tlsSocketPtr, parsePtr);
            break;
#endif

        case TLS_EXT_RENEGOTIATION_INFO:
            break;
#if 0u
        case TLS_EXT_SIGNATURE_ALG:
            ret = TcpIp_TlsParseClientSignatureAlgorithmsExtension(tlsSocketPtr, extPtr + 4u, ext_size);
            break;
#endif
#if (STD_ON == TLS_ENCRYPT_THEN_MAC)
        case TLS_EXT_ENCRYPT_THEN_MAC:
            tlsSocketPtr->socketTlsContext.encryptThenMac = TRUE;
            break;
#endif

        case TLS_EXT_SUPPORTED_VERSIONS:
            /* ciphersuite is already selected here, only check if provided version is in support list */
            ret = TcpIp_TlsParseSupportedVersionExt(tlsSocketPtr, parsePtr);
            break;

        case TLS_EXT_KEY_SHARE:
            ret = TcpIp_TlsParseKeyShareExt(tlsSocketPtr, parsePtr);
            break;

        default: /* PRQA S 2016 */ /* VL_QAC_EmptyClause */
            break;
        }

        if (TLS_RETURN_OK != ret)
        {
            return ret;
        }

        extLen -= extInnerLen + 4u;
        parsePtr += extInnerLen;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_Tls12DecryptNotifyRecord(TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
    sint32                   ret        = TLS_RETURN_OK;
    Std_ReturnType           Std_Return = E_OK;
    uint16                   readLen = 0u, plainTextLen = 0u, remainder = 0u; /* PRQA S 4603 */ /* VL_TcpIp_4603 */
    uint32                   pBufLen                      = 0u;
    uint8                    buffer[READ_WRITE_BLOCK_LEN] = {0u}, paddingLen = 0u, MacLen = 32u;
    struct pbuf*             buf      = NULL_PTR;
    uint8 *                  parseKey = NULL_PTR, *parseMACKey = NULL_PTR;
    TcpIp_TlsSocketDataType* tlsSocketPtr = sockeRuntimePtr->tlsPtr;
    tlsContext*              context      = &tlsSocketPtr->socketTlsContext;
    uint32                   decryptJobId = context->ciphersuiteWorkerPtr->CipherCsmDecryptJobId;
    uint32                   decryptKeyId = context->ciphersuiteWorkerPtr->CipherCsmDecryptKeyId;

    /* choose diffrent key and iv according to ConnectionType */
    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        parseKey    = context->server_write_key;
        parseMACKey = context->server_write_MAC_key;
    }
    else
    {
        parseKey    = context->client_write_key;
        parseMACKey = context->client_write_MAC_key;
    }
    TCPIP_UNUSED_ARG(parseMACKey);

    /*
     *	TLS 1.2 GenericBlockCipher struct:
     *	SRTUCT {
     *		opaque IV[SecurityParameters.record_iv_length];
     *		block-ciphered struct {
     *			opaque content[TLSCompressed.length];
     *			opaque MAC[SecurityParameters.mac_length];
     *			uint8 padding[GenericBlockCipher.padding_length];
     *			uint8 padding_length;
     *			};
     *		} GenericBlockCipher;
     */

    /* Read record header and IV, inRemainingLen==0 means previous record has been fully read */
    if (0u == context->inRemainingLen)
    {
        ret = TcpIp_TlsGetRecordHdr(tlsSocketPtr);
        if (0 == ret)
        {
            return TLS_ERR_NET_BAD_INPUT_DATA;
        }

        if (context->inRecordContentType != TLS_MSG_TYPE_APPLICATION_DATA)
        {
            return TLS_ERR_NET_BAD_INPUT_DATA;
        }

        readLen = TcpIp_TlsBioRecvCallBack(tlsSocketPtr, context->recordIV, (uint16)context->record_IV_length);
        if (readLen != context->record_IV_length)
        {
            return TLS_ERR_NET_BAD_INPUT_DATA;
        }
        context->inRemainingLen -= readLen;
    }

    while (context->inRemainingLen)
    {
        /*	read block of 256B, if there's any remainder, then process remainder first
         *	for CBC mode, protocol requires padding length at most 256B(255B padding + 1B padding_length), and at least
         * 0 length of padding and MAC is at most 256+32=288 considering only 1 block(AES128 16B, AES256 32B) is
         * satisfied so here, we process block of 256B every time
         */
        remainder = context->inRemainingLen & (READ_WRITE_BLOCK_LEN - 1u);
        if (remainder)
        {
            readLen = remainder;
        }
        else
        {
            readLen = READ_WRITE_BLOCK_LEN;
        }

        if (tlsSocketPtr->rx->tot_len < readLen)
        {
            /* pbuf data length is less than expected, wait for more data */
            return TLS_ERR_SSL_WANT_READ;
        }

        readLen = TcpIp_TlsBioRecvCallBack(tlsSocketPtr, context->inRecordContentStart, readLen);

        /* key element set */
        Std_Return = Csm_KeyElementSet(decryptKeyId, CRYPTO_KE_CIPHER_KEY, parseKey, context->write_key_len);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        Std_Return = Csm_KeyElementSet(decryptKeyId, CRYPTO_KE_CIPHER_IV, context->recordIV, context->record_IV_length);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        (void)Csm_KeySetValid(decryptKeyId);

        /* decrypt data */
        pBufLen    = READ_WRITE_BLOCK_LEN;
        Std_Return = Csm_Decrypt(
            decryptJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            context->inRecordContentStart,
            readLen,
            buffer,
            &pBufLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_NET_BAD_INPUT_DATA;
        }

        context->inRemainingLen -= readLen;
        if (0u == context->inRemainingLen)
        {
            /* all data read, then parse MAC and padding length */
            paddingLen   = buffer[readLen - 1u];
            plainTextLen = readLen - MacLen - paddingLen - 1u;
        }
        else
        {
            /* update IV */
            (void)IStdLib_MemCpy(
                context->recordIV,
                context->inRecordContentStart + readLen - context->record_IV_length,
                context->record_IV_length);
            plainTextLen = readLen;
        }

        buf = pbuf_alloc(PBUF_RAW, (u16_t)plainTextLen, PBUF_POOL);
        if (NULL_PTR == buf)
        {
            return TLS_ERR_NET_BUFFER_TOO_SMALL;
        }

        (void)IStdLib_MemCpy(buf->payload, buffer, plainTextLen);
        tlsSocketPtr->flags |= TLS_FLAGS_UPPER_CALLED;
        /* shall call upper layer */
        (void)TcpIp_TcpNotifyUpRxIndication(sockeRuntimePtr, &buf);
        (void)pbuf_free(buf);
        buf = NULL_PTR;
    }

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType
    TcpIp_Tls12EncryptWriteRecord(TcpIp_TlsSocketDataType* tlsSocketPtr, const uint8* plainTextPtr, uint16 plainTextLen)
{
    Std_ReturnType                              Std_Return = E_OK;
    uint32                                      ret        = 0u;
    tlsContext*                                 context    = &tlsSocketPtr->socketTlsContext;
    uint16                                      writeLen = 0u, remainingLen = plainTextLen;
    uint8                                       MACData[TLS_MAC_ADD] = {0u};
    uint8 *                                     writeKey = NULL_PTR, *writeMACKey = NULL_PTR;
    uint8                                       CBCBlockSize = 0u, paddingLen = 0u, MacLen = 32u;
    uint32                                      MACDataLen           = TLS_MAC_ADD;
    const TcpIp_TlsCiphersuiteWorkerConfigType* ciphersuiteWorkerPtr = context->ciphersuiteWorkerPtr;
    uint32                                      encryptJobId         = ciphersuiteWorkerPtr->CipherCsmEncryptJobId;
    uint32                                      encryptKeyId         = ciphersuiteWorkerPtr->CipherCsmEncryptKeyId;

    uint32 resultLen = (uint32)context->record_IV_length;
    Std_Return       = TcpIp_TlsCsmRandomGenerate(context->recordIV, &resultLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    uint16 IV_length = (uint16)resultLen;

    /* choose diffrent key and iv according to ConnectionType */
    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        writeKey    = context->client_write_key;
        writeMACKey = context->client_write_MAC_key;
    }
    else
    {
        writeKey    = context->server_write_key;
        writeMACKey = context->server_write_MAC_key;
    }

    /* key element set */
    Std_Return = Csm_KeyElementSet(encryptKeyId, CRYPTO_KE_CIPHER_KEY, writeKey, context->write_key_len);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(encryptKeyId);

    /*
     *   TLS 1.2 MAC construction, not actual C code:
     *   MAC(MAC_write_key, seq_num +
     *   TLSCompressed.type +
     *   TLSCompressed.version +
     *   TLSCompressed.length +
     *   TLSCompressed.fragment);
     */
    uint8  inputData[TLS_OUT_CONTENT_LEN] = {0u};
    uint8* inputDataPtr                   = inputData;

    /* to be optimized */
    inputDataPtr[0u] = (context->seqNum >> 56u) & 0xffu;
    inputDataPtr[1u] = (context->seqNum >> 48u) & 0xffu;
    inputDataPtr[2u] = (context->seqNum >> 40u) & 0xffu;
    inputDataPtr[3u] = (context->seqNum >> 32u) & 0xffu;
    inputDataPtr[4u] = (context->seqNum >> 24u) & 0xffu;
    inputDataPtr[5u] = (context->seqNum >> 16u) & 0xffu;
    inputDataPtr[6u] = (context->seqNum >> 8u) & 0xffu;
    inputDataPtr[7u] = context->seqNum & 0xffu;
    inputDataPtr += 8u;

    inputDataPtr[0u] = context->outRecordContentType;
    inputDataPtr[1u] = TLS_MAJOR_VERSION_3;
    inputDataPtr[2u] = context->minorVersion;
    inputDataPtr[3u] = (plainTextLen >> 8u) & 0xffu;
    inputDataPtr[4u] = plainTextLen & 0xffu;
    inputDataPtr += 5u;

    uint32 macGenerateJobId = ciphersuiteWorkerPtr->CipherCsmMacGenerateJobId;
    uint32 macGenerateKeyId = ciphersuiteWorkerPtr->CipherCsmMacGenerateKeyId;
    Std_Return = Csm_KeyElementSet(macGenerateKeyId, CRYPTO_KE_MAC_KEY, writeMACKey, context->write_MAC_key_len);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    Csm_KeySetValid(macGenerateKeyId);

    (void)IStdLib_MemCpy(inputDataPtr, plainTextPtr, plainTextLen);
    inputDataPtr += plainTextLen;
    uint16 inputDataLen = 8u + 5u + plainTextLen;

    Std_Return = Csm_MacGenerate(
        macGenerateJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        inputData,
        inputDataLen,
        MACData,
        &MACDataLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
#if (TLS_USE_CSM_API != STD_ON) /* output length should be set by csm, but csm dosen't set now */
    MACDataLen = 32u;
#endif

    (void)IStdLib_MemCpy(inputData, plainTextPtr, plainTextLen);
    /*
     *	TLS 1.2  GenericBlockCipher, not actual C code:
     *	struct {
     *		opaque IV[SecurityParameters.record_iv_length];
     *		block-ciphered struct {
     *			opaque content[TLSCompressed.length];
     *			opaque MAC[SecurityParameters.mac_length];
     *			uint8 padding[GenericBlockCipher.padding_length];
     *			uint8 padding_length;
     *			};
     *		} GenericBlockCipher;
     */
    CBCBlockSize                    = 16u; /* only for AES128 */
    paddingLen                      = CBCBlockSize - ((plainTextLen + MacLen + 1u) % CBCBlockSize);
    context->outRecordContentLength = IV_length + plainTextLen + (uint16)MacLen + (uint16)paddingLen + 1u;
    TcpIp_TlsBuildRecordHeader(context);

    (void)IStdLib_MemCpy(context->outRecordContentStart, context->recordIV, IV_length);

    ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outRecordHdrStart, TLS_RECORD_HEADER_LENGTH + IV_length);
    if (ret <= 0u)
    {
        return E_NOT_OK;
    }

    while (remainingLen)
    {
        /* key element set */
        Std_Return = Csm_KeyElementSet(encryptKeyId, CRYPTO_KE_CIPHER_IV, context->recordIV, IV_length);
        if (E_OK != Std_Return)
        {
            return Std_Return;
        }
        Csm_KeySetValid(encryptKeyId);

        writeLen     = (remainingLen < READ_WRITE_BLOCK_LEN) ? remainingLen : READ_WRITE_BLOCK_LEN;
        inputDataPtr = inputData;

        if (remainingLen == writeLen)
        {
            inputDataPtr += writeLen;

            (void)IStdLib_MemCpy(inputDataPtr, MACData, MACDataLen);
            inputDataPtr += MACDataLen;

            inputDataPtr[0u] = paddingLen;
            inputDataPtr++;

            IStdLib_MemSet(inputDataPtr, paddingLen, paddingLen);
            inputDataLen = writeLen + (uint16)MACDataLen + 1u + paddingLen;
        }
        else
        {
            inputDataLen = writeLen;
        }

        /* encrypt data */
        resultLen  = inputDataLen;
        Std_Return = Csm_Encrypt(
            encryptJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            inputData,
            inputDataLen,
            context->outRecordContentStart,
            &resultLen);
        if (E_OK != Std_Return)
        {
            return Std_Return;
        }
        context->outRecordContentLength = (uint16)resultLen;

        ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outRecordContentStart, inputDataLen);
        if (ret <= 0u)
        {
            return E_NOT_OK;
        }

        /* update IV for CBC mode */
        (void)IStdLib_MemCpy(
            context->recordIV,
            context->outRecordContentStart + inputDataLen - context->record_IV_length,
            context->record_IV_length);

        remainingLen -= writeLen;
    }

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_Tls13Decrypt(tlsContext* context)
{
    Std_ReturnType Std_Return           = E_NOT_OK;
    uint8          nonce[TLS_NONCE_LEN] = {0u}, additionalData[TLS_ADD_DATA_LEN] = {0u}, tag[TLS_TAG_LENGTH] = {0u};
    uint16         cipherTextLen = 0u, plainTextLen = 0u, paddingLen = 0u;
    uint8 *        decryptKey = NULL_PTR, *decryptIV = NULL_PTR;

    cipherTextLen = context->inRecordContentLength - TLS_TAG_LENGTH;

    /* choose diffrent key and iv */
    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        decryptKey = context->server_write_key;
        decryptIV  = context->server_write_IV;
    }
    else
    {
        decryptKey = context->client_write_key;
        decryptIV  = context->client_write_IV;
    }

    plainTextLen = cipherTextLen - paddingLen - 1u;

    (void)IStdLib_MemCpy(tag, context->inRecordContentStart + cipherTextLen, TLS_TAG_LENGTH);

    /*
     RFC 8446 - 5.3.  Per-Record Nonce
      The per-record nonce for the AEAD construction is formed as follows:
      1.  The 64-bit record sequence number is encoded in network byte
           order and padded to the left with zeros to iv_length.
      2.  The padded sequence number is XORed with either the static
           client_write_iv or server_write_iv (depending on the role).
    */
    nonce[4u]  = (context->peerSeqNum >> 56u) & 0xffu;
    nonce[5u]  = (context->peerSeqNum >> 48u) & 0xffu;
    nonce[6u]  = (context->peerSeqNum >> 40u) & 0xffu;
    nonce[7u]  = (context->peerSeqNum >> 32u) & 0xffu;
    nonce[8u]  = (context->peerSeqNum >> 24u) & 0xffu;
    nonce[9u]  = (context->peerSeqNum >> 16u) & 0xffu;
    nonce[10u] = (context->peerSeqNum >> 8u) & 0xffu;
    nonce[11u] = context->peerSeqNum & 0xffu;

    TcpIp_Xor(TLS_NONCE_LEN, nonce, decryptIV, nonce);

    /*
     TLS 1.3 Additional Data Construction:
     additional_data = TLSCiphertext.opaque_type ||
     TLSCiphertext.legacy_record_version ||
     TLSCiphertext.length
    */
    additionalData[0u] = TLS_MSG_TYPE_APPLICATION_DATA;
    additionalData[1u] = TLS_MAJOR_VERSION_3;
    additionalData[2u] = TLS_MINOR_VERSION_3;
    additionalData[3u] = (context->inRecordContentLength >> 8u) & 0xffu;
    additionalData[4u] = context->inRecordContentLength & 0xffu;

    uint8  buffer[TLS_RECORD_SIZE_LIMIT] = {0u};
    uint32 bufferLen                     = TLS_RECORD_SIZE_LIMIT;
    uint32 decryptKeyId                  = context->ciphersuiteWorkerPtr->CipherCsmDecryptKeyId;

    /* key element set */
    Std_Return = Csm_KeyElementSet(decryptKeyId, CRYPTO_KE_CIPHER_KEY, decryptKey, context->write_key_len);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
    Std_Return = Csm_KeyElementSet(decryptKeyId, CRYPTO_KE_CIPHER_IV, nonce, context->write_IV_len);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
    Std_Return = Csm_KeySetValid(decryptKeyId);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    uint32                  decryptJobId = context->ciphersuiteWorkerPtr->CipherCsmDecryptJobId;
    Crypto_VerifyResultType verifyResult = CRYPTO_E_VER_NOT_OK;

    Std_Return = Csm_AEADDecrypt(
        decryptJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        context->inRecordContentStart,
        cipherTextLen,
        additionalData,
        TLS_ADD_DATA_LEN,
        tag,
        TLS_TAG_LENGTH,
        buffer,
        &bufferLen,
        &verifyResult);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
    if (CRYPTO_E_VER_OK != verifyResult)
    {
        return TLS_ERR_INVALID_MAC;
    }

    (void)IStdLib_MemCpy(context->inRecordContentStart, buffer, plainTextLen);
    context->inRecordContentType   = buffer[plainTextLen];
    context->inRecordContentLength = plainTextLen;
    context->peerSeqNum++;

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_Tls13DecryptNotifyRecord(TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
    sint32                                      ret                  = TLS_RETURN_OK;
    struct pbuf*                                buf                  = NULL_PTR;
    TcpIp_TlsSocketDataType*                    tlsSocketPtr         = sockeRuntimePtr->tlsPtr;
    tlsContext*                                 context              = &tlsSocketPtr->socketTlsContext;
    const TcpIp_TlsCiphersuiteWorkerConfigType* ciphersuiteWorkerPtr = context->ciphersuiteWorkerPtr;

    /* Read record header, inRemainingLen==0 means previous record has been fully read */
    if (0u == context->inRemainingLen)
    {
        ret = TcpIp_TlsGetRecordHdr(tlsSocketPtr);
        if (ret < 0)
        {
            return ret;
        }
        else if (0 == ret)
        {
            return TLS_ERR_SSL_WANT_READ;
        }
        else
        {
            /* No action required */
        }

        if (context->inRecordContentType != TLS_MSG_TYPE_APPLICATION_DATA)
        {
            return TLS_ERR_NET_BAD_INPUT_DATA;
        }
    }

    if (tlsSocketPtr->rx->tot_len < context->inRemainingLen)
    {
        /* pbuf data length is less than expected, wait for more data */
        return TLS_ERR_SSL_WANT_READ;
    }

    uint16 readLen = TcpIp_TlsBioRecvCallBack(tlsSocketPtr, context->inRecordContentStart, context->inRemainingLen);
    if (readLen != context->inRemainingLen)
    {
        return TLS_ERR_NET_BAD_INPUT_DATA;
    }
    context->inRemainingLen -= readLen;

    /*  AEAD is mandatoryin TLS 1.3.
        Though AES-GCM is stream cipher, we can't decrypt it byte by byte.
        Because the tag is attached at the end of the decrypted data.
        We must read all the data to get the tag, then decrypt is possible.
        Considering the memory limit, we set record size limit to 256.
    */
    ret = TcpIp_Tls13Decrypt(context);
    if (TLS_RETURN_OK != ret)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    if (TLS_MSG_TYPE_HANDSHAKE == context->inRecordContentType)
    {
        uint8* parsePtr = context->inRecordContentStart;

        if (TLS_HS_TYPE_NEW_SESSION_TICKET == parsePtr[0u])
        {
            return TLS_RETURN_OK;
        }
    }

    /* alloc new pbuf to transfer to upper layer*/
    buf = pbuf_alloc(PBUF_RAW, context->inRecordContentLength, PBUF_POOL);
    if (NULL_PTR == buf)
    {
        return TLS_ERR_NET_BUFFER_TOO_SMALL;
    }

    (void)IStdLib_MemCpy(buf->payload, context->inRecordContentStart, context->inRecordContentLength);
    tlsSocketPtr->flags |= TLS_FLAGS_UPPER_CALLED;
    /* shall call upper layer */
    (void)TcpIp_TcpNotifyUpRxIndication(sockeRuntimePtr, &buf);
    (void)pbuf_free(buf);

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType
    TcpIp_Tls13EncryptWriteRecord(TcpIp_TlsSocketDataType* tlsSocketPtr, const uint8* plainTextPtr, uint16 plainTextLen)
{
    Std_ReturnType Std_Return                       = E_OK;
    sint32         ret                              = TLS_RETURN_OK;
    uint8          inputData[TLS_RECORD_SIZE_LIMIT] = {0u};
    uint8          nonce[TLS_NONCE_LEN] = {0u}, additionalData[TLS_ADD_DATA_LEN] = {0u}, tag[TLS_TAG_LENGTH] = {0u};
    uint32         tagLen               = TLS_TAG_LENGTH;
    uint16         TLSinnerPlainTextLen = 0u, TLSCipherTextLen = 0u, paddingLen = 0u;
    tlsContext*    context    = &tlsSocketPtr->socketTlsContext;
    uint8 *        encryptKey = NULL_PTR, *encryptIV = NULL_PTR;

    /* choose diffrent key and iv */
    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        encryptKey = context->client_write_key;
        encryptIV  = context->client_write_IV;
    }
    else
    {
        encryptKey = context->server_write_key;
        encryptIV  = context->server_write_IV;
    }

    /* plaintext */
    (void)IStdLib_MemCpy(inputData, plainTextPtr, plainTextLen);
    inputData[plainTextLen] = context->outRecordContentType;

    /*
     RFC 8446 - 5.2.  Record Payload Protection
     The length of the plaintext is greater than
     the corresponding TLSPlaintext.length due to the inclusion of
     TLSInnerPlaintext.type and any padding supplied by the sender.
    */
    TLSinnerPlainTextLen = plainTextLen + paddingLen + 1u;

    /*
     RFC 8446 - 5.3.  Per-Record Nonce
      The per-record nonce for the AEAD construction is formed as follows:
      1.  The 64-bit record sequence number is encoded in network byte
           order and padded to the left with zeros to iv_length.
      2.  The padded sequence number is XORed with either the static
           client_write_iv or server_write_iv (depending on the role).
    */
    nonce[4u]  = (context->seqNum >> 56u) & 0xffu;
    nonce[5u]  = (context->seqNum >> 48u) & 0xffu;
    nonce[6u]  = (context->seqNum >> 40u) & 0xffu;
    nonce[7u]  = (context->seqNum >> 32u) & 0xffu;
    nonce[8u]  = (context->seqNum >> 24u) & 0xffu;
    nonce[9u]  = (context->seqNum >> 16u) & 0xffu;
    nonce[10u] = (context->seqNum >> 8u) & 0xffu;
    nonce[11u] = context->seqNum & 0xffu;

    TcpIp_Xor(TLS_NONCE_LEN, nonce, encryptIV, nonce);

    /*************************************************
     TLS 1.3 Additional Data Construction:
     additional_data := TLSCiphertext.opaque_type ||
         TLSCiphertext.legacy_record_version ||
         TLSCiphertext.length
    **************************************************/
    TLSCipherTextLen   = TLSinnerPlainTextLen + TLS_TAG_LENGTH;
    additionalData[0u] = TLS_MSG_TYPE_APPLICATION_DATA;
    additionalData[1u] = TLS_MAJOR_VERSION_3;
    additionalData[2u] = TLS_MINOR_VERSION_3;
    additionalData[3u] = (TLSCipherTextLen >> 8u) & 0xffu;
    additionalData[4u] = TLSCipherTextLen & 0xffu;

    uint32 bufferLen    = TLS_RECORD_SIZE_LIMIT;
    uint32 encryptKeyId = context->ciphersuiteWorkerPtr->CipherCsmEncryptKeyId;

    /* key element set */
    Std_Return = Csm_KeyElementSet(encryptKeyId, CRYPTO_KE_CIPHER_KEY, encryptKey, context->write_key_len);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
    Std_Return = Csm_KeyElementSet(encryptKeyId, CRYPTO_KE_CIPHER_IV, nonce, context->write_IV_len);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
    Std_Return = Csm_KeySetValid(encryptKeyId);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    uint32 encryptJobId = context->ciphersuiteWorkerPtr->CipherCsmEncryptJobId;
    Std_Return          = Csm_AEADEncrypt(
        encryptJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        inputData,
        TLSinnerPlainTextLen,
        additionalData,
        TLS_ADD_DATA_LEN,
        context->outRecordContentStart,
        &bufferLen,
        tag,
        &tagLen);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    (void)IStdLib_MemCpy(&context->outRecordContentStart[TLSinnerPlainTextLen], tag, TLS_TAG_LENGTH);

    context->outRecordContentLength = TLSCipherTextLen;
    context->outRecordContentType   = TLS_MSG_TYPE_APPLICATION_DATA;
    TcpIp_TlsBuildRecordHeader(context);

    ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outPBuf->payload, context->outTotalLen);
    if (ret <= 0)
    {
        return E_NOT_OK;
    }

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsBuildCertificateBody(tlsContext* context, KeyM_CertDataType* certificateDataPtr)
{
    uint8* writePtr   = context->outRecordContentStart;
    uint32 lengthFied = 0u, curCertLen = 0u, totalCertLen = 0u;
    uint16 certExtLen = 0u;

    /*     Content
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   6   total certificate length
     *     7  .   9   certificate0 length
     *    10  .   n   certificate0
     *    n+1 .   n+4 certificate1 length
     *                certificate1
     */
    writePtr[0u] = TLS_HS_TYPE_CERTIFICATE;
    /* skip handshake length first */
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /* certificate request context length */
        writePtr[0u] = 0u;
        writePtr++;
    }

    /* total certificates length */
    totalCertLen = certificateDataPtr->certDataLength + 3u;
    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        totalCertLen += 2u + (uint32)certExtLen; /* certificate extension Len */
    }
    writePtr[0u] = (totalCertLen >> 16u) & 0xffu;
    writePtr[1u] = (totalCertLen >> 8u) & 0xffu;
    writePtr[2u] = totalCertLen & 0xffu;
    writePtr += 3u;

    /* certificate0 length */
    curCertLen   = certificateDataPtr->certDataLength;
    writePtr[0u] = (curCertLen >> 16u) & 0xffu;
    writePtr[1u] = (curCertLen >> 8u) & 0xffu;
    writePtr[2u] = curCertLen & 0xffu;
    writePtr += 3u;

    (void)IStdLib_MemCpy(writePtr, certificateDataPtr->certData, certificateDataPtr->certDataLength);
    writePtr += certificateDataPtr->certDataLength;

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /* certificate extension len */
        writePtr[0u] = (certExtLen >> 8u) & 0xffu;
        writePtr[1u] = certExtLen & 0xffu;
        writePtr += 2u;
    }

    context->outRecordContentLength    = writePtr - context->outRecordContentStart;
    lengthFied                         = context->outRecordContentLength - TLS_HANDSHAKE_HEADER_LENGTH;
    context->outRecordContentStart[1u] = (lengthFied >> 16u) & 0xffu;
    context->outRecordContentStart[2u] = (lengthFied >> 8u) & 0xffu;
    context->outRecordContentStart[3u] = lengthFied & 0xffu;
    context->outRecordContentType      = TLS_MSG_TYPE_HANDSHAKE;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsWriteCertificate(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32            ret             = TLS_RETURN_OK;
    Std_ReturnType    Std_Return      = E_OK;
    tlsContext*       context         = &tlsSocketPtr->socketTlsContext;
    KeyM_CertDataType certificateData = {.certData = NULL_PTR, .certDataLength = 0u};
    uint16            certId          = 0u;

    if (context->certificateIdentityPtr)
    {
        certId = context->certificateIdentityPtr->CipherKeyMLocalCertificateId;
    }
    else
    {
        uint32 certListId = context->connectionConfigPtr->CertificateIdentityIdList[0u];
        certId            = TcpIp_TlsCfgPtr->CertificateIdentityPtr[certListId].CipherKeyMLocalCertificateId;
    }

    uint8 certDataGet[TLS_CERT_MAX_LENGTH] = {0u};
    certificateData.certData               = &certDataGet;
    certificateData.certDataLength         = TLS_CERT_MAX_LENGTH;
    Std_Return                             = KeyM_GetCertificate(certId, &certificateData); /*SWS_TCPIP_00316*/
    if (E_NOT_OK == Std_Return)
    {
        return TLS_ERR_CERTIFICATE_REQUIRED;
    }

    TcpIp_TlsBuildCertificateBody(context, &certificateData);

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
#if (TLS_USE_CSM_API == STD_ON)
        Std_Return = TcpIp_TlsUpdateHSHash(context);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#else
        (void)IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;
#endif
        /* In TLS 1.3 certificate needs to be encrypted */
        Std_Return = TcpIp_Tls13EncryptWriteRecord(
            tlsSocketPtr,
            context->outRecordContentStart,
            context->outRecordContentLength);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        /* TLS_SERVER_CERTIFICATE -> TLS_CERTIFICATE_VERIFY */
        context->state = TLS_CERTIFICATE_VERIFY;
    }
    else
    {
#if (TLS_USE_CSM_API == STD_ON)
        Std_Return = TcpIp_TlsUpdateHSHash(context);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#else
        (void)IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;
#endif
        TcpIp_TlsBuildRecordHeader(context);
        ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outPBuf->payload, context->outTotalLen);
        if (ret <= 0)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
        {
            /* TLS_CLIENT_CERTIFICATE -> TLS_CLIENT_KEY_EXCHANGE */
            context->state = TLS_CLIENT_KEY_EXCHANGE;
        }
        else
        {
            /* TLS_SERVER_CERTIFICATE -> TLS_SERVER_KEY_EXCHANGE */
            context->state = TLS_SERVER_KEY_EXCHANGE;
        }
    }

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_TlsMasterSecretDerive(tlsContext* context)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint8          seed[TLS_RANDOM_LENGTH << 1u];
    (void)IStdLib_MemCpy(seed, context->clientRandom, TLS_RANDOM_LENGTH);
    (void)IStdLib_MemCpy(seed + TLS_RANDOM_LENGTH, context->serverRandom, TLS_RANDOM_LENGTH);

    Std_Return = TcpIp_TlsPRF(
        context,
        context->preMasterSecret,
        context->masterSecretLen,
        TLS_LABEL_MASTER_SECRET,
        CONST_STRLEN(TLS_LABEL_MASTER_SECRET),
        seed,
        64u,
        context->masterSecret,
        48u);

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_Tls12WriteKeyCalculation(tlsContext* context)
{
    Std_ReturnType Std_Return                           = E_NOT_OK;
    uint8          keyBlock[192u]                       = {0u};
    uint8*         keyBlockPtr                          = keyBlock;
    uint32         keyBlockLen                          = 0u;
    uint8          randomField[TLS_RANDOM_LENGTH << 1u] = {0u};

    keyBlockLen = (context->write_key_len << 1u) + (context->write_MAC_key_len << 1u) + ((context->write_IV_len << 1u));
    (void)IStdLib_MemCpy(randomField, context->serverRandom, TLS_RANDOM_LENGTH);
    (void)IStdLib_MemCpy(randomField + TLS_RANDOM_LENGTH, context->clientRandom, TLS_RANDOM_LENGTH);

    /* calculate master secret */
    Std_Return = TcpIp_TlsPRF(
        context,
        context->masterSecret,
        TLS_MASTER_SECRET_LEN,
        (const uint8*)TLS_LABEL_KEY_EXPANSION,
        CONST_STRLEN(TLS_LABEL_KEY_EXPANSION),
        randomField,
        TLS_RANDOM_LENGTH << 1u,
        keyBlock,
        keyBlockLen);
    if (E_OK == Std_Return)
    {
        (void)IStdLib_MemCpy(context->client_write_MAC_key, keyBlockPtr, context->write_MAC_key_len);

        keyBlockPtr += context->write_MAC_key_len;
        (void)IStdLib_MemCpy(context->server_write_MAC_key, keyBlockPtr, context->write_MAC_key_len);

        keyBlockPtr += context->write_MAC_key_len;
        (void)IStdLib_MemCpy(context->client_write_key, keyBlockPtr, context->write_key_len);

        keyBlockPtr += context->write_key_len;
        (void)IStdLib_MemCpy(context->server_write_key, keyBlockPtr, context->write_key_len);

        if (context->write_IV_len)
        {
            /* some ciphersuites need IV */
            keyBlockPtr += context->write_key_len;
            (void)IStdLib_MemCpy(context->client_write_IV, keyBlockPtr, context->write_IV_len);

            keyBlockPtr += context->write_IV_len;
            (void)IStdLib_MemCpy(context->server_write_IV, keyBlockPtr, context->write_IV_len);
        }
    }

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/*************************************************************************
RFC 8446 Sec 7.1.	Key Schedule

          0
          |
          v
PSK ->  HKDF-Extract = Early Secret
          |
          +-----> Derive-Secret(., "ext binder" | "res binder", "")
          |                     = binder_key
          |
          +-----> Derive-Secret(., "c e traffic", ClientHello)
          |                     = client_early_traffic_secret
          |
          +-----> Derive-Secret(., "e exp master", ClientHello)
          |                     = early_exporter_master_secret
          v
    Derive-Secret(., "derived", "")
          |
          v
(EC)DHE -> HKDF-Extract = Handshake Secret
          |
          +-----> Derive-Secret(., "c hs traffic",
          |                     ClientHello...ServerHello)
          |                     = client_handshake_traffic_secret
          |
          +-----> Derive-Secret(., "s hs traffic",
          |                     ClientHello...ServerHello)
          |                     = server_handshake_traffic_secret
          v
    Derive-Secret(., "derived", "")
          |
          v
0 -> HKDF-Extract = Master Secret
          |
          +-----> Derive-Secret(., "c ap traffic",
          |                     ClientHello...server Finished)
          |                     = client_application_traffic_secret_0
          |
          +-----> Derive-Secret(., "s ap traffic",
          |                     ClientHello...server Finished)
          |                     = server_application_traffic_secret_0
          |
          +-----> Derive-Secret(., "exp master",
          |                     ClientHello...server Finished)
          |                     = exporter_master_secret
          |
          +-----> Derive-Secret(., "res master",
                                ClientHello...client Finished)
                                = resumption_master_secret
****************************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_Tls13HSSecretDerive(tlsContext* context)
{
    Std_ReturnType Std_Return                             = E_NOT_OK;
    uint32         outputLen                              = context->hashLen;
    uint8          extractedSecret[TLS13_MAX_HASH_LENGTH] = {0u}, derivedSecret[TLS13_MAX_HASH_LENGTH] = {0u},
          zeroString[TLS13_MAX_HASH_LENGTH] = {0u};

    /**** Early Secret ****/
    Std_Return = TcpIp_HKDFExtract(
        context,
        zeroString,
        context->hashLen,
        zeroString,
        context->hashLen,
        extractedSecret,
        &outputLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    Std_Return = TcpIp_DeriveSecret(
        context,
        extractedSecret,
        context->hashLen,
        TLS_LABEL_DERIVED,
        CONST_STRLEN(TLS_LABEL_DERIVED),
        TLS_LABEL_EMPTY,
        0u,
        derivedSecret);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /**** Handshake Secret ****/
    Std_Return = TcpIp_HKDFExtract(
        context,
        derivedSecret,
        context->hashLen,
        context->ECDHEKey,
        context->DHKeyLen,
        extractedSecret,
        &outputLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /************************ client **************************/
    /* client_handshake_traffic_secret */
    Std_Return = TcpIp_DeriveSecret(
        context,
        extractedSecret,
        context->hashLen,
        TLS_LABEL_C_HS_TRAFFIC,
        CONST_STRLEN(TLS_LABEL_C_HS_TRAFFIC),
        context->handshake_messages,
        context->handshake_messagesLen,
        derivedSecret);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* client_write_key */
    Std_Return = TcpIp_HKDFExpandLabel(
        context,
        derivedSecret,
        context->hashLen,
        TLS_LABEL_KEY,
        CONST_STRLEN(TLS_LABEL_KEY),
        TLS_LABEL_EMPTY,
        0u,
        context->client_write_key,
        context->write_key_len);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* client_write_iv */
    Std_Return = TcpIp_HKDFExpandLabel(
        context,
        derivedSecret,
        context->hashLen,
        TLS_LABEL_IV,
        CONST_STRLEN(TLS_LABEL_IV),
        TLS_LABEL_EMPTY,
        0u,
        context->client_write_IV,
        context->write_IV_len);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* finished_key  */
    Std_Return = TcpIp_HKDFExpandLabel(
        context,
        derivedSecret,
        context->hashLen,
        TLS_LABEL_FINISHED,
        CONST_STRLEN(TLS_LABEL_FINISHED),
        TLS_LABEL_EMPTY,
        0u,
        context->client_finished_key,
        context->hashLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /************************ server **************************/
    /* server_handshake_traffic_secret */
    Std_Return = TcpIp_DeriveSecret(
        context,
        extractedSecret,
        context->hashLen,
        TLS_LABEL_S_HS_TRAFFIC,
        CONST_STRLEN(TLS_LABEL_S_HS_TRAFFIC),
        context->handshake_messages,
        context->handshake_messagesLen,
        derivedSecret);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* server_write_key */
    Std_Return = TcpIp_HKDFExpandLabel(
        context,
        derivedSecret,
        context->hashLen,
        TLS_LABEL_KEY,
        CONST_STRLEN(TLS_LABEL_KEY),
        TLS_LABEL_EMPTY,
        0u,
        context->server_write_key,
        context->write_key_len);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* server_write_iv */
    Std_Return = TcpIp_HKDFExpandLabel(
        context,
        derivedSecret,
        context->hashLen,
        TLS_LABEL_IV,
        CONST_STRLEN(TLS_LABEL_IV),
        TLS_LABEL_EMPTY,
        0u,
        context->server_write_IV,
        context->write_IV_len);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* finished_key  */
    Std_Return = TcpIp_HKDFExpandLabel(
        context,
        derivedSecret,
        context->hashLen,
        TLS_LABEL_FINISHED,
        CONST_STRLEN(TLS_LABEL_FINISHED),
        TLS_LABEL_EMPTY,
        0u,
        context->server_finished_key,
        context->hashLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /**** Master Secret ****/
    Std_Return = TcpIp_DeriveSecret(
        context,
        extractedSecret,
        context->hashLen,
        TLS_LABEL_DERIVED,
        CONST_STRLEN(TLS_LABEL_DERIVED),
        TLS_LABEL_EMPTY,
        0u,
        derivedSecret);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    Std_Return = TcpIp_HKDFExtract(
        context,
        derivedSecret,
        context->hashLen,
        zeroString,
        context->hashLen,
        extractedSecret,
        &outputLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    (void)IStdLib_MemCpy(context->masterSecret, extractedSecret, outputLen);
    context->masterSecretLen = outputLen;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsHandshakeWrapUp(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    Std_ReturnType Std_Return                           = E_OK;
    tlsContext*    context                              = &tlsSocketPtr->socketTlsContext;
    uint8          derivedSecret[TLS13_MAX_HASH_LENGTH] = {0u};

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /* TLS 1.3 */
        /* client_application_traffic_secret_0 */
        Std_Return = TcpIp_DeriveSecret(
            context,
            context->masterSecret,
            context->masterSecretLen,
            TLS_LABEL_C_AP_TRAFFIC,
            CONST_STRLEN(TLS_LABEL_C_AP_TRAFFIC),
            context->handshake_messages,
            context->handshake_messagesLen,
            derivedSecret);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        Std_Return = TcpIp_HKDFExpandLabel(
            context,
            derivedSecret,
            context->hashLen,
            TLS_LABEL_KEY,
            CONST_STRLEN(TLS_LABEL_KEY),
            TLS_LABEL_EMPTY,
            0u,
            context->client_write_key,
            context->write_key_len);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        Std_Return = TcpIp_HKDFExpandLabel(
            context,
            derivedSecret,
            context->hashLen,
            TLS_LABEL_IV,
            CONST_STRLEN(TLS_LABEL_IV),
            TLS_LABEL_EMPTY,
            0u,
            context->client_write_IV,
            context->write_IV_len);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        /* server_application_traffic_secret_0 */
        Std_Return = TcpIp_DeriveSecret(
            context,
            context->masterSecret,
            context->masterSecretLen,
            TLS_LABEL_S_AP_TRAFFIC,
            CONST_STRLEN(TLS_LABEL_S_AP_TRAFFIC),
            context->handshake_messages,
            context->handshake_messagesLen,
            derivedSecret);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        Std_Return = TcpIp_HKDFExpandLabel(
            context,
            derivedSecret,
            context->hashLen,
            TLS_LABEL_KEY,
            CONST_STRLEN(TLS_LABEL_KEY),
            TLS_LABEL_EMPTY,
            0u,
            context->server_write_key,
            context->write_key_len);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        Std_Return = TcpIp_HKDFExpandLabel(
            context,
            derivedSecret,
            context->hashLen,
            TLS_LABEL_IV,
            CONST_STRLEN(TLS_LABEL_IV),
            TLS_LABEL_EMPTY,
            0u,
            context->server_write_IV,
            context->write_IV_len);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        context->seqNum     = 0u;
        context->peerSeqNum = 0u;
    }

    /* TLS_HANDSHAKE_WRAPUP -> TLS_HANDSHAKE_DONE */
    tlsSocketPtr->socketTlsContext.state               = TLS_HANDSHAKE_DONE;
    TcpIp_TlsHandshakeBusyStatus[context->handshakeId] = FALSE;

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TLsWriteChangeCipherSpec(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret      = TLS_RETURN_OK;
    tlsContext* context  = &tlsSocketPtr->socketTlsContext;
    uint8*      writePtr = context->outPBuf->payload;

    writePtr = context->outRecordContentStart;

    /* record content */
    /* only 1 byte for change cipher spec */
    writePtr[0u] = 1u;
    writePtr++;

    context->outRecordContentLength = writePtr - context->outRecordContentStart;
    context->outRecordContentType   = TLS_MSG_TYPE_CHANGE_CIPHER_SPEC;
    TcpIp_TlsBuildRecordHeader(context);

    ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outPBuf->payload, context->outTotalLen);
    if (ret > 0)
    {
        ret = TLS_RETURN_OK;
    }
    else
    {
        return ret;
    }

    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        /* TLS_CLIENT_CHANGE_CIPHER_SPEC -> TLS_CLIENT_FINISHED */
        context->state = TLS_CLIENT_FINISHED;
    }
    else
    {
        if (TLS_MINOR_VERSION_4 == context->minorVersion)
        {
            /* TLS_SERVER_CHANGE_CIPHER_SPEC -> TLS_ENCRYPTED_EXTENSIONS */
            context->state = TLS_ENCRYPTED_EXTENSIONS;
        }
        else
        {
            /* TLS_SERVER_CHANGE_CIPHER_SPEC -> TLS_SERVER_FINISHED */
            context->state = TLS_SERVER_FINISHED;
        }
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsWriteHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    if (TLS_MINOR_VERSION_4 == tlsSocketPtr->socketTlsContext.minorVersion)
    {
        /* TLS 1.3 */
        return TcpIp_Tls13WriteHandshakeFinished(tlsSocketPtr);
    }
    else
    {
        /* TLS 1.2 */
        return TcpIp_Tls12WriteHandshakeFinished(tlsSocketPtr);
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_Tls12WriteHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret                          = TLS_RETURN_OK;
    Std_ReturnType Std_Return                   = E_OK;
    uint8          hashResult[TLS_HASH_MAX_LEN] = {0u};
    uint32         resultLen                    = TLS_HASH_MAX_LEN;
    const uint8*   finishLabel                  = NULL_PTR;
    tlsContext*    context                      = &tlsSocketPtr->socketTlsContext;
    uint32         verifyDataLen                = 0u;
    uint8*         writePtr                     = context->outRecordContentStart;
    uint32         hashJobId                    = context->handshakePtr->CsmHashVerifyJobId;

    Std_Return = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        context->handshake_messages,
        context->handshake_messagesLen,
        hashResult,
        &resultLen);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    writePtr[0u] = TLS_HS_TYPE_FINISHED;
    /* skip handshake length first */
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        finishLabel = (const uint8*)TLS_LABEL_TLS12_CLIENT_FINISHED;
        /* TLS_CLIENT_FINISHED -> TLS_SERVER_CHANGE_CIPHER_SPEC */
        context->state = TLS_SERVER_CHANGE_CIPHER_SPEC;
    }
    else
    {
        finishLabel = (const uint8*)TLS_LABEL_TLS12_SERVER_FINISHED;
        /* TLS_SERVER_FINISHED -> TLS_HANDSHAKE_WRAPUP */
        context->state = TLS_HANDSHAKE_WRAPUP;
    }
    /*
     * RFC 5246 7.4.9 (Page 63) says 12 is the default length and ciphersuites
     * may define some other value. Currently (early 2016), no defined
     * moved to TLS 1.3 now) so we can keep the hardcoded 12 here.
     */
    verifyDataLen   = TLS12_VERIFY_DATA_LEN;
    context->seqNum = 0u;
    Std_Return      = TcpIp_TlsPRF(
        context,
        context->masterSecret,
        context->masterSecretLen,
        finishLabel,
        (uint32)strlen(finishLabel),
        hashResult,
        context->hashLen,
        writePtr,
        verifyDataLen);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    context->outRecordContentStart[1u] = (verifyDataLen >> 16u) & 0xffu;
    context->outRecordContentStart[2u] = (verifyDataLen >> 8u) & 0xffu;
    context->outRecordContentStart[3u] = verifyDataLen & 0xffu;
    context->outRecordContentLength    = verifyDataLen + TLS_HANDSHAKE_HEADER_LENGTH;

    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        /* client needs to calculate hash to verify server finished */
#if (TLS_USE_CSM_API == STD_ON)
        resultLen  = TLS_HASH_MAX_LEN;
        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_UPDATE,
            context->outRecordContentStart,
            context->outRecordContentLength,
            context->handshakeMsgHash,
            &resultLen);

        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_FINISH,
            context->outRecordContentStart,
            context->outRecordContentLength,
            context->handshakeMsgHash,
            &context->hashLen);
#else
        (void)IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;

        resultLen  = TLS_HASH_MAX_LEN;
        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            context->handshake_messages,
            context->handshake_messagesLen,
            context->handshakeMsgHash,
            &resultLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#endif
        ret = TLS_ERR_SSL_WANT_READ;
    }

    context->outRecordContentType = TLS_MSG_TYPE_HANDSHAKE;
    Std_Return =
        TcpIp_Tls12EncryptWriteRecord(tlsSocketPtr, context->outRecordContentStart, context->outRecordContentLength);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_Tls13WriteHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret                          = TLS_RETURN_OK;
    Std_ReturnType Std_Return                   = E_OK;
    uint8          hashResult[TLS_HASH_MAX_LEN] = {0u};
    uint32         resultLen                    = TLS_HASH_MAX_LEN;
    const uint8*   finishLabel                  = NULL_PTR;
    tlsContext*    context                      = &tlsSocketPtr->socketTlsContext;
    uint32         verifyDataLen                = 0u;
    uint8*         writePtr                     = context->outRecordContentStart;
    uint32         hashJobId                    = context->handshakePtr->CsmHashVerifyJobId;

    Std_Return = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        context->handshake_messages,
        context->handshake_messagesLen,
        hashResult,
        &resultLen);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    writePtr[0u] = TLS_HS_TYPE_FINISHED;
    /* skip handshake length first */
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    uint8* finishedKey = NULL_PTR;
    if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
    {
        /* TLS_CLIENT_FINISHED -> TLS_HANDSHAKE_WRAPUP */
        context->state  = TLS_HANDSHAKE_WRAPUP;
        finishedKey     = context->client_finished_key;
        context->seqNum = 0u;
    }
    else
    {
        /* TLS_SERVER_FINISHED -> TLS_CLIENT_CHANGE_CIPHER_SPEC */
        context->state = TLS_CLIENT_CHANGE_CIPHER_SPEC;
        finishedKey    = context->server_finished_key;
    }

    verifyDataLen           = context->hashLen;
    uint32 macGenerateKeyId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateKeyId;
    Std_Return              = Csm_KeyElementSet(macGenerateKeyId, CRYPTO_KE_MAC_KEY, finishedKey, context->hashLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    Csm_KeySetValid(macGenerateKeyId);

    uint32 macGenerateJobId = context->ciphersuiteWorkerPtr->CipherCsmMacGenerateJobId;
    Std_Return              = Csm_MacGenerate(
        macGenerateJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        hashResult,
        context->hashLen,
        writePtr,
        &verifyDataLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    context->outRecordContentStart[1u] = (verifyDataLen >> 16u) & 0xffu;
    context->outRecordContentStart[2u] = (verifyDataLen >> 8u) & 0xffu;
    context->outRecordContentStart[3u] = verifyDataLen & 0xffu;
    context->outRecordContentLength    = verifyDataLen + TLS_HANDSHAKE_HEADER_LENGTH;

    if (TLS_SERVER == context->connectionConfigPtr->ConnectionType)
    {
        /* server needs to calculate hash to verify client finished */
#if (TLS_USE_CSM_API == STD_ON)
        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_UPDATE,
            context->outRecordContentStart,
            context->outRecordContentLength,
            context->handshakeMsgHash,
            &resultLen);

        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_FINISH,
            context->outRecordContentStart,
            context->outRecordContentLength,
            context->handshakeMsgHash,
            &context->hashLen);
#else
        (void)IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;

        resultLen  = TLS_HASH_MAX_LEN;
        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            context->handshake_messages,
            context->handshake_messagesLen,
            context->handshakeMsgHash,
            &resultLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#endif
        ret = TLS_ERR_SSL_WANT_READ;
    }

    context->outRecordContentType = TLS_MSG_TYPE_HANDSHAKE;
    Std_Return =
        TcpIp_Tls13EncryptWriteRecord(tlsSocketPtr, context->outRecordContentStart, context->outRecordContentLength);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsParseChangeCipherSpec(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret      = TLS_RETURN_OK;
    tlsContext* context  = &tlsSocketPtr->socketTlsContext;
    uint8*      parsePtr = NULL;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    if (TLS_MSG_TYPE_CHANGE_CIPHER_SPEC != context->inRecordContentType)
    {
        return TLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC;
    }

    parsePtr = context->inRecordContentStart;

    if ((1u != context->inRecordContentLength) || (1u != parsePtr[0u]))
    {
        return TLS_ERR_BAD_HS_CLIENT_HELLO;
    }

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
        {
            /* TLS_CLIENT_CHANGE_CIPHER_SPEC -> TLS_ENCRYPTED_EXTENSIONS */
            context->state = TLS_ENCRYPTED_EXTENSIONS;
        }
        else
        {
            /* TLS_CLIENT_CHANGE_CIPHER_SPEC -> TLS_CLIENT_FINISHED */
            context->state = TLS_CLIENT_FINISHED;
        }
    }
    else
    {
        if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
        {
            /* TLS_SERVER_CHANGE_CIPHER_SPEC -> TLS_SERVER_FINISHED */
            context->state = TLS_SERVER_FINISHED;
        }
        else
        {
            /* TLS_CLIENT_CHANGE_CIPHER_SPEC -> TLS_CLIENT_FINISHED */
            context->state = TLS_CLIENT_FINISHED;
        }
    }

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsParseHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32                                      ret           = TLS_RETURN_OK;
    Std_ReturnType                              Std_Return    = E_OK;
    uint8                                       recordIV[32u] = {0u}, plainText[64u] = {0u};
    uint32                                      plainTextLen         = 64u;
    tlsContext*                                 context              = &tlsSocketPtr->socketTlsContext;
    uint8*                                      parsePtr             = NULL;
    const TcpIp_TlsCiphersuiteWorkerConfigType* ciphersuiteWorkerPtr = context->ciphersuiteWorkerPtr;
    uint32                                      decryptJobId         = ciphersuiteWorkerPtr->CipherCsmDecryptJobId;
    uint32                                      decryptKeyId         = ciphersuiteWorkerPtr->CipherCsmDecryptKeyId;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /* TLS 1.3 */
        ret = TcpIp_Tls13Decrypt(context);
        if (TLS_RETURN_OK != ret)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
        {
            /* TLS_SERVER_FINISHED -> TLS_CLIENT_CHANGE_CIPHER_SPEC */
            context->state = TLS_CLIENT_CHANGE_CIPHER_SPEC;
#if (TLS_USE_CSM_API == STD_ON)
            Std_Return = TcpIp_TlsUpdateHSHash(context);
            if (E_OK != Std_Return)
            {
                return TLS_ERR_BAD_HS_CERTIFICATE;
            }
#else
            (void)IStdLib_MemCpy(
                &context->handshake_messages[context->handshake_messagesLen],
                context->inRecordContentStart,
                context->inRecordContentLength);
            context->handshake_messagesLen += context->inRecordContentLength;
#endif
        }
        else
        {
            /* TLS_CLIENT_FINISHED -> TLS_HANDSHAKE_WRAPUP */
            context->state = TLS_HANDSHAKE_WRAPUP;
        }
    }
    else
    {
        /* TLS 1.2 */
        parsePtr = context->inRecordContentStart;

        (void)IStdLib_MemCpy(recordIV, parsePtr, 16u);
        parsePtr += 16u;

        Std_Return =
            Csm_KeyElementSet(decryptKeyId, CRYPTO_KE_CIPHER_KEY, context->client_write_key, context->write_key_len);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        Std_Return = Csm_KeyElementSet(decryptKeyId, CRYPTO_KE_CIPHER_IV, recordIV, context->record_IV_length);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        (void)Csm_KeySetValid(decryptKeyId);

        Std_Return = Csm_Decrypt(
            decryptJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            parsePtr,
            context->inRecordContentLength - 16u,
            plainText,
            &plainTextLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        if (TLS_CLIENT == context->connectionConfigPtr->ConnectionType)
        {
            /* TLS_SERVER_FINISHED -> TLS_HANDSHAKE_WRAPUP */
            context->state = TLS_HANDSHAKE_WRAPUP;
        }
        else
        {
            /* TLS_CLIENT_FINISHED -> TLS_SERVER_CHANGE_CIPHER_SPEC */
            context->state = TLS_SERVER_CHANGE_CIPHER_SPEC;

#if (TLS_USE_CSM_API == STD_ON)
            Std_Return = TcpIp_TlsUpdateHSHash(context);
            if (E_OK != Std_Return)
            {
                return TLS_ERR_BAD_HS_CERTIFICATE;
            }
#else
            (void)IStdLib_MemCpy(&context->handshake_messages[context->handshake_messagesLen], plainText, 16u);
            context->handshake_messagesLen += 16u;
#endif
        }
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsBufSetup(tlsContext* socketTlsContext)
{
    sint32 ret = TLS_RETURN_OK;

    socketTlsContext->inPBuf = pbuf_alloc(PBUF_RAW, TLS_IN_BUFFER_LEN, PBUF_RAM);

    if (NULL_PTR == socketTlsContext->inPBuf)
    {
        return TLS_ERR_ALLOC_FAILED;
    }

    socketTlsContext->outPBuf = pbuf_alloc(PBUF_RAW, TLS_OUT_BUFFER_LEN, PBUF_RAM);
    if (NULL_PTR == socketTlsContext->outPBuf)
    {
        pbuf_free(socketTlsContext->inPBuf);
        return TLS_ERR_ALLOC_FAILED;
    }

    socketTlsContext->inBufPtr             = socketTlsContext->inPBuf->payload;
    socketTlsContext->inRecordHdrStart     = socketTlsContext->inPBuf->payload;
    socketTlsContext->inRecordContentStart = socketTlsContext->inRecordHdrStart + TLS_RECORD_HEADER_LENGTH;

    socketTlsContext->outRecordHdrStart     = socketTlsContext->outPBuf->payload;
    socketTlsContext->outRecordContentStart = socketTlsContext->outRecordHdrStart + TLS_RECORD_HEADER_LENGTH;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#endif /* (TCPIP_TCP_TLS_ENABLED == STD_ON) */
