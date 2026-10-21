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
 **  @description        : Implementation for TLS server
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
/* PRQA S 2889 EOF */                   /* VL_QAC_MultiReturn */
/* PRQA S 3120, 3132 EOF */             /* VL_QAC_MagicNum */
/* PRQA S 2982 EOF */                   /* VL_TcpIp_2982 */
/* PRQA S 2985 EOF */                   /* VL_TcpIp_2985 */
/* PRQA S 0488, 0317 EOF */             /* VL_TcpIp_0488, VL_TcpIp_0317 */
/* PRQA S 0686 EOF */                   /* VL_TcpIp_0686 */
/* PRQA S 0499 EOF */                   /* VL_TcpIp_0499 */
/* PRQA S 1277 EOF */                   /* VL_TcpIp_1277 */
/* PRQA S 4491, 4461, 4434, 4397 EOF */ /* VL_TcpIp_4491, VL_TcpIp_4461, VL_TcpIp_4434, VL_TcpIp_4397 */
/* PRQA S 2981, 2053 EOF */             /* VL_TcpIp_2981, VL_TcpIp_2053 */
/* PRQA S 4115, 3344 EOF */             /* VL_TcpIp_4115, VL_TcpIp_3344 */
/* PRQA S 3200 EOF */                   /* VL_TcpIp_3200 */
/* PRQA S 1258 EOF */                   /* VL_TcpIp_1258 */
/* PRQA S 3673, 3678 EOF */             /* VL_TcpIp_3673, VL_TcpIp_3678 */
/* PRQA S 0553 EOF */                   /* VL_QAC_UnUsedFiles */

/*******************************************************************************
**                      Include Section                                       **
*******************************************************************************/

#include "TcpIp_Cfg.h"

#if (TCPIP_TCP_TLS_ENABLED == STD_ON)
#include "TcpIp_Tls.h"
#include "TcpIp_Internal.h"
#include "Csm.h"

/*******************************************************************************
**                      Private Function Declarations                         **
*******************************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseClientHello(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Build and send server hello packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerHello(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send Server Hello Done packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerHelloDone(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send Server Hello packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsBuildServerHello(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build server hello extension.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 *				writePtr	: pointer to the write data.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsBuildSHExtension(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** writePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send Server Key Exchange packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		 Parse Client Key Exchange packet.
 * @param[in]	 tlsSocketPtr	: TLS socket pointer.
 * @return 	 tls error code.
 * @reentrant	 TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 * @trace None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseClientKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send Server Certificate Request packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerCertificateRequest(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send Server Certificate Verify packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerCertificateVerify(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Parse the encrypted PreMasterSecret from the client.
 *
 * @param[in]  context        TLS context.
 * @param[in]  encryptedData  Encrypted PreMasterSecret buffer.
 * @param[in]  len            Length of encrypted data in bytes.
 * @return TLS_RETURN_OK on success; negative TLS error code otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32
    TcpIp_TlsParseClientEncryptedPreMasterSecret(tlsContext* context, const uint8* encryptedData, uint32 len);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief       Build server hello session id.
 * @param[in]   tlsSocketPtr   : TLS socket pointer.
                writePtr	: pointer to the write data.
 * @return      void.
 * @reentrant   TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL void TcpIp_TlsBuildSHSessionId(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** writePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send Encrypted Extension packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteEncryptedExt(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/*******************************************************************************
**                      Private Function Definitions                          **
*******************************************************************************/

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL
sint32 TcpIp_TlsParseClientEncryptedPreMasterSecret(tlsContext* context, const uint8* encryptedData, uint32 len)
{
    Std_ReturnType Std_Return                    = E_OK;
    uint8          result[TLS_MASTER_SECRET_LEN] = {0u};
    uint32         resultLength                  = TLS_MASTER_SECRET_LEN;
    uint32         keyExchangeJobId              = context->handshakePtr->CsmKeyExchangeDecryptJobId;
    uint32         keyExchangeKeyId              = context->handshakePtr->CsmKeyExchangeDecryptKeyId;

    Std_Return = Csm_KeySetValid(keyExchangeKeyId);

    /* decrypt pre master secret */
    Std_Return =
        Csm_Decrypt(keyExchangeJobId, CRYPTO_OPERATIONMODE_SINGLECALL, encryptedData, len, result, &resultLength);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    IStdLib_MemCpy(context->preMasterSecret, result, TLS_MASTER_SECRET_LEN);
    context->masterSecretLen = TLS_MASTER_SECRET_LEN;

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerCertificateVerify(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    Std_ReturnType Std_Return                       = E_OK;
    tlsContext*    context                          = &tlsSocketPtr->socketTlsContext;
    uint8          transcriptHash[TLS_HASH_MAX_LEN] = {0u}, signDataInput[162u] = {0u};
    uint32         lengthFied = 0u, signDataInputLen = 0u, transcriptHashLen = TLS_HASH_MAX_LEN;
    uint8 *        writePtr = context->outRecordContentStart, *signDataInputPtr = signDataInput;
    uint32         hashJobId = context->handshakePtr->CsmHashVerifyJobId;

    Std_Return = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        context->handshake_messages,
        context->handshake_messagesLen,
        transcriptHash,
        &transcriptHashLen);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    writePtr[0u] = TLS_HS_TYPE_CERTIFICATE_VERIFY;
    /* skip handshake length first */
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    /*************************************************
     CertificateVerify struct:
     struct {
        SignatureScheme algorithm;
        opaque signature<0..2^16-1>;
     } CertificateVerify;
    **************************************************/

    /* SignatureScheme */
    writePtr[0u] = (TLS_RSA_PSS_RSAE_SHA256 >> 8u) & 0xffu;
    writePtr[1u] = TLS_RSA_PSS_RSAE_SHA256 & 0xffu;
    writePtr += 2u;

    /*************************************************
    The digital signature is then computed over the concatenation of:
    -  A string that consists of octet 32 (0x20) repeated 64 times
    -  The context string
    -  A single 0 byte which serves as the separator
    -  The content to be signed

    The context string for a server signature is
    "TLS 1.3, server CertificateVerify".  The context string for a
    client signature is "TLS 1.3, client CertificateVerify".
    **************************************************/
    uint32 verifyStrLen = sizeof(TLS_LABEL_TLS13_SERVER_VERIFY);
    IStdLib_MemSet(signDataInputPtr, 0x20u, 64u);
    signDataInputPtr += 64u;
    IStdLib_MemCpy(signDataInputPtr, TLS_LABEL_TLS13_SERVER_VERIFY, verifyStrLen);
    signDataInputPtr += verifyStrLen;
    IStdLib_MemCpy(signDataInputPtr, transcriptHash, context->hashLen);
    signDataInputPtr += context->hashLen;

    /* sign for data */
    signDataInputLen                    = signDataInputPtr - signDataInput;
    uint8  signResult[TLS_SIGN_MAX_LEN] = {0u};
    uint32 signDataOutputLen            = TLS_SIGN_MAX_LEN;
    uint32 signJobId                    = context->handshakePtr->CsmKeyExchangeSignatureGenerateJobId;
    uint32 signKeyId                    = context->handshakePtr->CsmKeyExchangeSignatureGenerateKeyId;

    Csm_KeySetValid(signKeyId);

    Std_Return = Csm_SignatureGenerate(
        signJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        signDataInput,
        signDataInputLen,
        signResult,
        &signDataOutputLen);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    /* signature length */
    writePtr[0u] = (signDataOutputLen >> 8u) & 0xffu;
    writePtr[1u] = signDataOutputLen & 0xffu;
    writePtr += 2u;

    /* signature */
    IStdLib_MemCpy(writePtr, signResult, signDataOutputLen);
    writePtr += signDataOutputLen;

    context->outRecordContentLength    = writePtr - context->outRecordContentStart;
    lengthFied                         = context->outRecordContentLength - TLS_HANDSHAKE_HEADER_LENGTH;
    context->outRecordContentStart[1u] = (lengthFied >> 16u) & 0xffu;
    context->outRecordContentStart[2u] = (lengthFied >> 8u) & 0xffu;
    context->outRecordContentStart[3u] = lengthFied & 0xffu;

    IStdLib_MemCpy(
        &context->handshake_messages[context->handshake_messagesLen],
        context->outRecordContentStart,
        context->outRecordContentLength);
    context->handshake_messagesLen += context->outRecordContentLength;

    context->outRecordContentType = TLS_MSG_TYPE_HANDSHAKE;
    Std_Return =
        TcpIp_Tls13EncryptWriteRecord(tlsSocketPtr, context->outRecordContentStart, context->outRecordContentLength);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    /* TLS_CERTIFICATE_VERIFY -> TLS_SERVER_FINISHED */
    tlsSocketPtr->socketTlsContext.state = TLS_SERVER_FINISHED;

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send Server Hello Done packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerHelloDone(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret      = TLS_RETURN_OK;
    tlsContext* context  = &tlsSocketPtr->socketTlsContext;
    uint8*      writePtr = context->outRecordContentStart;

    /* record content */
    writePtr[0u] = TLS_HS_TYPE_SERVER_HELLO_DONE;
    /* handshake length */
    writePtr[1u] = 0u;
    writePtr[2u] = 0u;
    writePtr[3u] = 0u;
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    context->outRecordContentLength = writePtr - context->outRecordContentStart;
    context->outRecordContentType   = TLS_MSG_TYPE_HANDSHAKE;
    TcpIp_TlsBuildRecordHeader(context);

    /* TLS_SERVER_HELLO_DONE -> TLS_CLIENT_KEY_EXCHANGE, skip TLS_CLIENT_CERTIFICATE */
    tlsSocketPtr->socketTlsContext.state = TLS_CLIENT_KEY_EXCHANGE;

    ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outPBuf->payload, context->outTotalLen);
    if (ret > 0)
    {
#if (TLS_USE_CSM_API == STD_ON)
        Std_ReturnType Std_Return = TcpIp_TlsUpdateHSHash(context);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#else
        IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;
#endif
        /* server hello message sent, wait for client message */
        ret = TLS_ERR_SSL_WANT_READ;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseClientKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret                   = TLS_RETURN_OK;
    Std_ReturnType Std_Return            = E_OK;
    const uint8*   parsePtr              = NULL;
    uint16         encryptedPreMasterLen = 0u;
    tlsContext*    context               = &tlsSocketPtr->socketTlsContext;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    if (TLS_MSG_TYPE_HANDSHAKE != context->inRecordContentType)
    {
        return TLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE;
    }

    parsePtr = context->inRecordContentStart;

    /* handshake type check */
    if (TLS_HS_TYPE_CLIENT_KEY_EXCHANGE != parsePtr[0u])
    {
        return TLS_ERR_BAD_HS_CLIENT_HELLO;
    }
    parsePtr += 4u;

    encryptedPreMasterLen = ((uint16)parsePtr[0u] << 8u) | parsePtr[1u];
    parsePtr += 2u;

    if (TLS_KEY_EXCHANGE_RSA == context->KeyExchange)
    {
        ret = TcpIp_TlsParseClientEncryptedPreMasterSecret(context, parsePtr, encryptedPreMasterLen);
        if (TLS_RETURN_OK != ret)
        {
            return ret;
        }
    }
    else if (TLS_KEY_EXCHANGE_ECDHE == context->KeyExchange)
    {
        // ECDHE
    }
    else
    {
        /* No action required */
    }

    /* Derive master secret according to pre master secret */
    Std_Return = TcpIp_TlsMasterSecretDerive(context);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    /* Derive write key and IV according to master secret and random */
    Std_Return = TcpIp_Tls12WriteKeyCalculation(context);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    /* TLS_CLIENT_KEY_EXCHANGE -> TLS_CLIENT_CHANGE_CIPHER_SPEC */
    tlsSocketPtr->socketTlsContext.state = TLS_CLIENT_CHANGE_CIPHER_SPEC;

#if (TLS_USE_CSM_API == STD_ON)
    Std_Return = TcpIp_TlsUpdateHSHash(context);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
#else
    IStdLib_MemCpy(
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
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerCertificateRequest(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    /* not support SCR now */

    /* TLS_CERTIFICATE_REQUEST -> TLS_SERVER_HELLO_DONE */
    tlsSocketPtr->socketTlsContext.state = TLS_SERVER_HELLO_DONE;
    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32 ret = TLS_RETURN_OK;

    /* RSA kx dosen't need server kx */
    if (tlsSocketPtr->socketTlsContext.KeyExchange != TLS_KEY_EXCHANGE_RSA)
    {
        /* build and send. */
    }

    /* TLS_SERVER_KEY_EXCHANGE -> TLS_CERTIFICATE_REQUEST */
    tlsSocketPtr->socketTlsContext.state = TLS_CERTIFICATE_REQUEST;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsWriteEncryptedExt(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret        = TLS_RETURN_OK;
    Std_ReturnType Std_Return = E_OK;
    tlsContext*    context    = &tlsSocketPtr->socketTlsContext;
    uint8*         writePtr   = context->outRecordContentStart;

    /* Currently, no extension need to be encrypted, but empty content still need to encrypted */

    writePtr[0u] = TLS_HS_TYPE_ENCRYPTED_EXTENSIONS;
    /* HS content length */
    writePtr[1u] = 0u;
    writePtr[2u] = 0u;
    writePtr[3u] = 2u;
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    /* extensions length */
    writePtr[0u] = 0u;
    writePtr[1u] = 0u;
    writePtr += 2u;

    context->outRecordContentLength = writePtr - context->outRecordContentStart;

#if (TLS_USE_CSM_API == STD_ON)
    Std_Return = TcpIp_TlsUpdateHSHash(context);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
#else
    IStdLib_MemCpy(
        &context->handshake_messages[context->handshake_messagesLen],
        context->outRecordContentStart,
        context->outRecordContentLength);
    context->handshake_messagesLen += context->outRecordContentLength;
#endif

    context->seqNum               = 0u;
    context->outRecordContentType = TLS_MSG_TYPE_HANDSHAKE;
    Std_Return =
        TcpIp_Tls13EncryptWriteRecord(tlsSocketPtr, context->outRecordContentStart, context->outRecordContentLength);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    /* TLS_ENCRYPTED_EXTENSIONS -> TLS_SERVER_CERTIFICATE */
    context->state = TLS_SERVER_CERTIFICATE;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsBuildSHSessionId(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** writePtr)
{
    const tlsContext* context      = &tlsSocketPtr->socketTlsContext;
    uint8 *           tempWritePtr = *writePtr, seesionIdLen = context->sessionIdLen;

    if (TLS_MINOR_VERSION_3 == context->minorVersion)
    {
        /* session id len set to 0 */
        tempWritePtr[0u] = 0u;
        tempWritePtr++;
    }
    else
    {
        /* TLS 1.3 session field is necessary */
        tempWritePtr[0u] = seesionIdLen;
        tempWritePtr++;

        if (seesionIdLen)
        {
            IStdLib_MemCpy(tempWritePtr, context->sessionId, seesionIdLen);
            tempWritePtr += seesionIdLen;
        }
    }

    *writePtr = tempWritePtr;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsBuildSHExtension(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** writePtr)
{
    Std_ReturnType Std_Return   = E_NOT_OK;
    uint16         extensionLen = 0u;
    uint8 *        tempWritePtr = *writePtr, *extensionLenPtr = *writePtr;
    tlsContext*    context = &tlsSocketPtr->socketTlsContext;

    /* skip length */
    tempWritePtr += 2u;

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /*************** supported vsersion: TLS 1.3 ***************/
        tempWritePtr[0u] = (TLS_EXT_SUPPORTED_VERSIONS >> 8u) & 0xffu;
        tempWritePtr[1u] = TLS_EXT_SUPPORTED_VERSIONS & 0xffu;
        tempWritePtr[2u] = 0u;
        tempWritePtr[3u] = 2u;

        tempWritePtr[4u] = TLS_MAJOR_VERSION_3;
        tempWritePtr[5u] = TLS_MINOR_VERSION_4;
        tempWritePtr += 6u;

        /*************** key share ***************/
        uint32 keyExchangeLen = TLS_X25519_KEY_LEN;
        tempWritePtr[0u]      = (TLS_EXT_KEY_SHARE >> 8u) & 0xffu;
        tempWritePtr[1u]      = TLS_EXT_KEY_SHARE & 0xffu;
        tempWritePtr[2u]      = ((keyExchangeLen + 4u) >> 8u) & 0xffu;
        tempWritePtr[3u]      = (keyExchangeLen + 4u) & 0xffu;

        tempWritePtr[4u] = (ECDHE_GROUP_X25519 >> 8u) & 0xffu;
        tempWritePtr[5u] = ECDHE_GROUP_X25519 & 0xffu;
        tempWritePtr[6u] = (keyExchangeLen >> 8u) & 0xffu;
        tempWritePtr[7u] = keyExchangeLen & 0xffu;
        tempWritePtr += 8u;

        uint8 dhPublicKey[TLS_DH_KEY_MAX_LEN] = {0u};
        uint8 sharedKey[TLS_DH_KEY_MAX_LEN]   = {0u};
        if (NULL == context->handshakePtr) /* handshakePtr should set in ciphersuite phase */
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        uint32 exchangeKeyId = context->handshakePtr->CsmKeyExchangeKeyId;
        if (0xFFFFFFFFu == exchangeKeyId) /* TLS 1.3 should configure exchange key */
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        Std_Return = Csm_KeySetValid(exchangeKeyId);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

#if (TLS_USE_CSM_API == STD_ON)
        /* Generate private key */
        Std_Return = Csm_KeyGenerate(exchangeKeyId);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#endif
        /* Generate public key according to private key */
        Std_Return = Csm_KeyExchangeCalcPubVal(exchangeKeyId, dhPublicKey, &keyExchangeLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        /* Generate shared key */
        Std_Return = Csm_KeyExchangeCalcSecret(exchangeKeyId, context->ECDHEKey, keyExchangeLen);
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
        Std_Return = Csm_KeyElementGet(exchangeKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, sharedKey, &keyExchangeLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        IStdLib_MemCpy(context->ECDHEKey, sharedKey, keyExchangeLen);
        IStdLib_MemCpy(tempWritePtr, dhPublicKey, keyExchangeLen);
        tempWritePtr += keyExchangeLen;
    }

    extensionLen = (uint16)(tempWritePtr - extensionLenPtr - 2); /* PRQA S 4393 */ /* VL_TcpIp_4393 */

    extensionLenPtr[0u] = (extensionLen >> 8u) & 0xffu;
    extensionLenPtr[1u] = extensionLen & 0xffu;

    /* PRQA S 4393 */ /* VL_TcpIp_4393 */
    *writePtr = tempWritePtr;

    return TLS_RETURN_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsBuildServerHello(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret        = TLS_RETURN_OK;
    Std_ReturnType Std_Return = E_NOT_OK;
    tlsContext*    context    = &tlsSocketPtr->socketTlsContext;
    uint8*         writePtr   = NULL_PTR;
    uint32         lengthFied = 0u;

    writePtr = context->outRecordContentStart;

    /*     Content
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     */
    writePtr[0u] = TLS_HS_TYPE_SERVER_HELLO;
    /* skip handshake length first */
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    writePtr[0u] = TLS_MAJOR_VERSION_3;
    writePtr[1u] = TLS_MINOR_VERSION_3;
    writePtr += 2u;

    /* genetate random filed */
    Std_Return = TcpIp_TlsGenerateRandomNumber(tlsSocketPtr);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
    IStdLib_MemCpy(writePtr, context->serverRandom, 32u);
    writePtr += TLS_RANDOM_LENGTH;

    /*   38  .  38     session id length
     *   39  . 38+n    session id
     *  39+n . 40+n    chosen ciphersuite
     *  41+n . 41+n    chosen compression alg.
     *  42+n . 43+n    extensions length
     *  44+n . 43+n+m  extensions */

    TcpIp_TlsBuildSHSessionId(tlsSocketPtr, &writePtr);

    /* ciphersuite */
    writePtr[0u] = (context->ciphersuiteDefinitionPtr->CiphersuiteId >> 8u) & 0xffu;
    writePtr[1u] = context->ciphersuiteDefinitionPtr->CiphersuiteId & 0xffu;
    writePtr += 2u;

    /* compression alg */
    writePtr[0u] = TLS_COMPRESS_NULL;
    writePtr++;

    ret = TcpIp_TlsBuildSHExtension(tlsSocketPtr, &writePtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    /* todo : negotiate recordSizeLimit */
    context->recordSizeLimit = 0xFFFFu;

    context->outRecordContentLength = writePtr - context->outRecordContentStart;
    context->outRecordContentType   = TLS_MSG_TYPE_HANDSHAKE;
    TcpIp_TlsBuildRecordHeader(context);

    /* handshake length */
    lengthFied                         = (uint32)context->outRecordContentLength - TLS_HANDSHAKE_HEADER_LENGTH;
    context->outRecordContentStart[1u] = (lengthFied >> 16u) & 0xffu;
    context->outRecordContentStart[2u] = (lengthFied >> 8u) & 0xffu;
    context->outRecordContentStart[3u] = lengthFied & 0xffu;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsWriteServerHello(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret        = TLS_RETURN_OK;
    Std_ReturnType Std_Return = E_NOT_OK;
    tlsContext*    context    = &tlsSocketPtr->socketTlsContext;

    ret = TcpIp_TlsBuildServerHello(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outPBuf->payload, context->outTotalLen);
    if (ret > 0)
    {
#if (TLS_USE_CSM_API == STD_ON)
        Std_Return = TcpIp_TlsUpdateHSHash(context);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#else
        IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;
#endif
        ret = TLS_RETURN_OK;
    }

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /* now we can calculate secrets for handshake
         * TLS 1.3 encrypts some packets in handshake such as encrypted Extension
         */
        Std_Return = TcpIp_Tls13HSSecretDerive(context);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        /* TLS_SERVER_HELLO -> TLS_SERVER_CHANGE_CIPHER_SPEC */
        tlsSocketPtr->socketTlsContext.state = TLS_SERVER_CHANGE_CIPHER_SPEC;
    }
    else
    {
        /* TLS_SERVER_HELLO -> TLS_SERVER_CERTIFICATE */
        tlsSocketPtr->socketTlsContext.state = TLS_SERVER_CERTIFICATE;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse client hello packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseClientHello(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret                  = TLS_RETURN_OK;
    uint8       compressionMethodLen = 0u;
    uint8*      parsePtr             = NULL;
    tlsContext* context              = &tlsSocketPtr->socketTlsContext;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    if (TLS_MSG_TYPE_HANDSHAKE != context->inRecordContentType)
    {
        return TLS_ERR_BAD_HS_CLIENT_HELLO;
    }

    /*  ClientHello layer:
     *     0  .   1   protocol version
     *     2  .  33   random bytes (starting with 4 bytes of Unix time)
     *    34  .  35   session id length (1 byte)
     *    35  . 34+x  session id
     *    ..  .  ..   ciphersuite list length (2 bytes)
     *    ..  .  ..   ciphersuite list
     *    ..  .  ..   compression alg. list length (1 byte)
     *    ..  .  ..   compression alg. list
     *    ..  .  ..   extensions length (2 bytes, optional)
     *    ..  .  ..   extensions (optional)
     */

    ret = TcpIp_TlsVersionCheck(context);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }
    /* skip length/version */
    parsePtr = context->inRecordContentStart;

    /* handshake type check */
    if (TLS_HS_TYPE_CLIENT_HELLO != parsePtr[0u])
    {
        return TLS_ERR_BAD_HS_CLIENT_HELLO;
    }

    parsePtr += 6u;
    IStdLib_MemCpy(context->clientRandom, parsePtr, TLS_RANDOM_LENGTH);
    parsePtr += TLS_RANDOM_LENGTH;

    context->sessionIdLen = parsePtr[0u];
    parsePtr++;
    if (context->sessionIdLen > 0u)
    {
        IStdLib_MemCpy(context->sessionId, parsePtr, context->sessionIdLen);
        parsePtr += context->sessionIdLen;
    }

    /* select client ciphersuite from list */
    ret = TcpIp_TlsCiphersuiteSelect(tlsSocketPtr, &parsePtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    /* AUTOSAR dosen't support data compression */
    compressionMethodLen = parsePtr[0u];
    parsePtr += compressionMethodLen + 1u;

    ret = TcpIp_TlsParseExtensions(tlsSocketPtr, parsePtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

#if (TLS_USE_CSM_API == STD_ON)
    uint32 hashJobId = context->handshakePtr->CsmHashVerifyJobId;
    uint32 resultLen = TLS_HASH_MAX_LEN;
    ret              = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_START,
        context->outRecordContentStart,
        context->outRecordContentLength,
        context->handshakeMsgHash,
        &resultLen);

    ret = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_UPDATE,
        context->outRecordContentStart,
        context->outRecordContentLength,
        context->handshakeMsgHash,
        &resultLen);
#else
    IStdLib_MemCpy(
        &context->handshake_messages[context->handshake_messagesLen],
        context->inRecordContentStart,
        context->inRecordContentLength);
    context->handshake_messagesLen += context->inRecordContentLength;
#endif

    /* TLS_CLIENT_HELLO -> TLS_SERVER_HELLO */
    tlsSocketPtr->socketTlsContext.state = TLS_SERVER_HELLO;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsServerHandshakeStep(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret        = TLS_RETURN_OK;
    tlsContext* curContext = &tlsSocketPtr->socketTlsContext;

    if (curContext->state == TLS_HANDSHAKE_DONE)
    {
        return TLS_ERR_BAD_INPUT_DATA;
    }

    switch (curContext->state)
    {
    case TLS_HELLO_REQUEST:
        curContext->state = TLS_CLIENT_HELLO;
        break;

    /*
     *  <==   ClientHello
     */
    case TLS_CLIENT_HELLO:
        ret = TcpIp_TlsParseClientHello(tlsSocketPtr);
        break;

    /*
     *  ==>   ServerHello
     * 	   Certificate
     * 	 ( ServerKeyExchange  )
     * 	 ( CertificateRequest )
     * 	   ServerHelloDone
     */
    case TLS_SERVER_HELLO:
        ret = TcpIp_TlsWriteServerHello(tlsSocketPtr);
        break;

    /*
     *  <== ( Certificate/Alert  )
     * 	   ClientKeyExchange
     * 	 ( CertificateVerify  )
     * 	   ChangeCipherSpec
     * 	   Finished
     */
    case TLS_SERVER_CERTIFICATE:
        ret = TcpIp_TlsWriteCertificate(tlsSocketPtr);
        break;

    case TLS_SERVER_KEY_EXCHANGE:
        ret = TcpIp_TlsWriteServerKeyExchange(tlsSocketPtr);
        break;

    case TLS_CERTIFICATE_REQUEST:
        ret = TcpIp_TlsWriteServerCertificateRequest(tlsSocketPtr);
        break;

    case TLS_SERVER_HELLO_DONE:
        ret = TcpIp_TlsWriteServerHelloDone(tlsSocketPtr);
        break;

    case TLS_CLIENT_CERTIFICATE:
        ret = TcpIp_TlsParseCertificate(tlsSocketPtr);
        break;

    case TLS_CLIENT_KEY_EXCHANGE:
        ret = TcpIp_TlsParseClientKeyExchange(tlsSocketPtr);
        break;

    case TLS_CERTIFICATE_VERIFY:
        ret = TcpIp_TlsWriteServerCertificateVerify(tlsSocketPtr);
        break;

    /*
     *  ==> ( NewSessionTicket )
     * 	   ChangeCipherSpec
     * 	   Finished
     */
    case TLS_CLIENT_CHANGE_CIPHER_SPEC:
        ret = TcpIp_TlsParseChangeCipherSpec(tlsSocketPtr);
        break;

    case TLS_CLIENT_FINISHED:
        ret = TcpIp_TlsParseHandshakeFinished(tlsSocketPtr);
        break;

    case TLS_SERVER_CHANGE_CIPHER_SPEC:
        ret = TcpIp_TLsWriteChangeCipherSpec(tlsSocketPtr);
        break;

    case TLS_ENCRYPTED_EXTENSIONS:
        ret = TcpIp_TlsWriteEncryptedExt(tlsSocketPtr);
        break;

    case TLS_SERVER_FINISHED:
        ret = TcpIp_TlsWriteHandshakeFinished(tlsSocketPtr);
        break;

    case TLS_FLUSH_BUFFERS:
        curContext->state = TLS_HANDSHAKE_WRAPUP;
        break;

    case TLS_HANDSHAKE_WRAPUP:
        ret = TcpIp_TlsHandshakeWrapUp(tlsSocketPtr);
        break;

    default:
        ret = TLS_ERR_BAD_INPUT_DATA;
        break;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#endif /* (TCPIP_TCP_TLS_ENABLED == STD_ON) */
