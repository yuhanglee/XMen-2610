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
 **  @file               : TcpIp_TlsClient.c
 **  @author             : pengfei.zhu
 **  @date               :
 **  @vendor             : isoft
 **  @description        : algorithm implementations of TLS
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
/* PRQA S 4461 EOF */                   /* VL_TcpIp_4461 */
/* PRQA S 1277 EOF */                   /* VL_TcpIp_1277 */
/* PRQA S 4491, 4461, 4434, 4397 EOF */ /* VL_TcpIp_4491, VL_TcpIp_4461, VL_TcpIp_4434, VL_TcpIp_4397 */
/* PRQA S 4115, 3344 EOF */             /* VL_TcpIp_4115, VL_TcpIp_3344 */
/* PRQA S 2981, 2053 EOF */             /* VL_TcpIp_2981, VL_TcpIp_2053 */
/* PRQA S 3200 EOF */                   /* VL_TcpIp_3200 */
/* PRQA S 1258 EOF */                   /* VL_TcpIp_1258 */
/* PRQA S 3673, 3678 EOF */             /*  VL_TcpIp_3673 */
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
**                      Global Variable Definitions                           **
*******************************************************************************/
#define TCPIP_START_SEC_VAR_CLEARED_PTR
#include "TcpIp_MemMap.h"
/**
 * @brief Global TLS configuration pointer (extern reference).
 * @range None
 */
extern const TcpIp_TlsConfigType* TcpIp_TlsCfgPtr;
#define TCPIP_STOP_SEC_VAR_CLEARED_PTR
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

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Handshake worker busy flags (extern reference).
 * @range None
 */
extern boolean TcpIp_TlsHandshakeBusyStatus[TCPIP_TLS_HANDSHAKE_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

/*******************************************************************************
**                      Private Function Declarations                         **
*******************************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse server certificate request packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseCertificateRequest(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse server hello done packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseServerHelloDone(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and write client key exchange packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteClientKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse server certificate verify packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseCertificateVerify(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse server hello packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 * 0->1:server_version;
 * 2->33:random (maybe including 4 bytes of Unix time);
 * 34->34:session_id length = n;
 * 35->34+n  session_id;
 * 35+n->36+n:cipher_suite;
 * 37+n->37+n:compression_method;
 * 38+n->39+n:extensions length (optional);
 * 40+n->.. : other extensions
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseServerHello(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Parse ServerKeyExchange when required by key exchange method.
 *
 * The ServerKeyExchange message carries additional parameters for
 * DHE/ECDHE. For RSA/DH/ECDH, nothing is required.
 *
 * @param[in] tlsSocketPtr TLS socket pointer.
 * @return TLS error code.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseServerKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Parse encrypted extensions from server.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 * TLS 1.3 has encrypted extension state, which is diffrent from TLS 1.2
 * some extensions can be encrypted
 * if no extension need to be encrypted, the content is still encrypted (length filed)
 */
TCPIP_LOCAL sint32 TcpIp_TlsParseEncryptedExt(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build and send client hello packet.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsWriteClientHello(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Build the signature_algorithms extension for ClientHello (TLS 1.2).
 *
 * @param[in]  tlsSocketPtr TLS socket pointer.
 * @param[in]  bufPtr       Buffer pointer to write the extension.
 * @param[out] olen         Output: number of bytes written to bufPtr.
 * @return None
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL void
    TcpIp_TlsBuildSignatureAlgorithmsExtension(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* bufPtr, uint32* olen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build client hello packet but not send.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsBuildClientHelloMessage(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#if (STD_ON == TCPIP_TLS_SERVER_NAME_INDICATION)
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Build the Server Name Indication (SNI) extension.
 *
 * @param[in]  serverName Server host name (ASCII, null-terminated).
 * @param[in]  bufPtr     Buffer pointer to write the extension.
 * @param[out] olen       Output: total extension length written.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL Std_ReturnType TcpIp_TlsWriteServerHostName(uint8* serverName, uint8* bufPtr, uint32* olen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#endif

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Build ClientHello extensions (TLS 1.2/1.3).
 *
 * @param[in]     tlsSocketPtr TLS socket pointer.
 * @param[in,out] writePtrPtr  Pointer to write pointer; advanced on success.
 * @return TLS error code.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsBuildCHExtensions(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** writePtrPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/*******************************************************************************
**                      Private Functions                                     **
*******************************************************************************/

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseCertificateRequest(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32 ret = TLS_RETURN_OK;

    TCPIP_UNUSED_ARG(tlsSocketPtr);
    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseServerHelloDone(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret      = TLS_RETURN_OK;
    tlsContext* context  = &tlsSocketPtr->socketTlsContext;
    uint8*      parsePtr = NULL;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    if (TLS_MSG_TYPE_HANDSHAKE != context->inRecordContentType)
    {
        return TLS_ERR_UNEXPECTED_MESSAGE;
    }

    parsePtr = context->inRecordContentStart;

    if (TLS_HS_TYPE_SERVER_HELLO_DONE != parsePtr[0u])
    {
        return TLS_ERR_UNEXPECTED_MESSAGE;
    }

    /* TLS_SERVER_HELLO_DONE -> TLS_CLIENT_KEY_EXCHANGE */
    context->state = TLS_CLIENT_KEY_EXCHANGE;

#if (TLS_USE_CSM_API == STD_ON)
    Std_ReturnType Std_Return = TcpIp_TlsUpdateHSHash(context);
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

/* PRQA S 3219 ++ */ /* VL_TcpIp_3219 */
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void
    TcpIp_TlsBuildSignatureAlgorithmsExtension(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* bufPtr, uint32* olen)
{
    uint8* msgPtr       = bufPtr;
    uint32 sig_alg_len  = 0u;
    uint8* sig_alg_list = bufPtr + 6u;
    *olen               = 0u;

    TCPIP_UNUSED_ARG(tlsSocketPtr);
    sig_alg_len += 2u;

    /* Prepare signature_algorithms extension (TLS 1.2) */
    /* PRQA S 2983, 3387, 3440 ++ */ /* VL_TcpIp_2983, VL_TcpIp_3387, VL_TcpIp_3440 */
    sig_alg_len                 = 0u;
    sig_alg_list[sig_alg_len++] = TLS_HASH_SHA256;
    sig_alg_list[sig_alg_len++] = TLS_SIG_RSA;
    *msgPtr++                   = (uint8)((TLS_EXT_SIGNATURE_ALG >> 8u) & 0xFFu);
    *msgPtr++                   = (uint8)((TLS_EXT_SIGNATURE_ALG) & 0xFFu);
    *msgPtr++                   = (uint8)(((sig_alg_len + 2u) >> 8u) & 0xFFu);
    *msgPtr++                   = (uint8)(((sig_alg_len + 2u)) & 0xFFu);
    *msgPtr++                   = (uint8)((sig_alg_len >> 8u) & 0xFFu);
    *msgPtr++                   = (uint8)((sig_alg_len) & 0xFFu);
    *olen                       = 6u + sig_alg_len;
    /* PRQA S 2983, 3387, 3440 -- */
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
/* PRQA S 3219 -- */

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseServerKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32 ret = TLS_RETURN_OK;
    TCPIP_UNUSED_ARG(tlsSocketPtr);

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseEncryptedExt(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret     = TLS_RETURN_OK;
    tlsContext* context = &tlsSocketPtr->socketTlsContext;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    context->peerSeqNum = 0u;
    ret                 = TcpIp_Tls13Decrypt(context);
    if (TLS_RETURN_OK != ret)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

#if (TLS_USE_CSM_API == STD_ON)
    Std_ReturnType Std_Return = TcpIp_TlsUpdateHSHash(context);
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

    /* TLS_ENCRYPTED_EXTENSIONS -> TLS_SERVER_CERTIFICATE */
    context->state = TLS_SERVER_CERTIFICATE;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsWriteClientKeyExchange(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret                            = TLS_RETURN_OK;
    Std_ReturnType Std_Return                     = E_NOT_OK;
    uint8*         writePtr                       = NULL_PTR;
    uint8          encryptedPremasterSecret[256u] = {0u};
    uint32         encryptedPremasterSecretLen = 256u, lengthFied = 0u;
    tlsContext*    context          = &tlsSocketPtr->socketTlsContext;
    uint32         keyExchangeJobId = context->handshakePtr->CsmKeyExchangeEncryptJobId;

    if (context->KeyExchange == TLS_KEY_EXCHANGE_RSA)
    {
        uint32 secretLen = 48u;
        /* generate preMasterSecret */
        Std_Return = TcpIp_TlsCsmRandomGenerate(context->preMasterSecret, &secretLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
        context->masterSecretLen     = (uint8)secretLen;
        context->preMasterSecret[0u] = TLS_MAJOR_VERSION_3;
        context->preMasterSecret[1u] = context->minorVersion;

        /* for RSA key exchange, client can caculate master secret after preMasterSecret generated */
        Std_Return = TcpIp_TlsMasterSecretDerive(context);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        /* calculate write key according to master secret */
        Std_Return = TcpIp_Tls12WriteKeyCalculation(context);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

#ifdef TCPIP_TLS_GTEST
        uint8 encrypted_premaster_secret[256u] = {
            0x03u, 0x20u, 0xA8u, 0x73u, 0x9Eu, 0x60u, 0xEDu, 0x65u, 0x41u, 0x81u, 0x34u, 0xF7u, 0xA5u, 0xC9u, 0xF1u,
            0xA6u, 0x95u, 0xB8u, 0xA7u, 0xD4u, 0x36u, 0x05u, 0x72u, 0x78u, 0xE4u, 0x85u, 0xF5u, 0xF3u, 0x8Eu, 0x21u,
            0xFDu, 0xCDu, 0x97u, 0x37u, 0xABu, 0x45u, 0x3Bu, 0x47u, 0xB0u, 0x76u, 0x67u, 0xA6u, 0xD6u, 0x91u, 0x80u,
            0x27u, 0xE3u, 0x9Du, 0xE5u, 0xDDu, 0x6Eu, 0x8Au, 0x23u, 0xEBu, 0x19u, 0x39u, 0x43u, 0xBDu, 0x28u, 0x7Au,
            0x05u, 0x92u, 0x93u, 0x47u, 0xB8u, 0x1Cu, 0x23u, 0x1Bu, 0x6Bu, 0xF7u, 0x98u, 0x26u, 0xC8u, 0x40u, 0x68u,
            0x36u, 0x92u, 0xF9u, 0xDEu, 0x6Bu, 0xFFu, 0xE5u, 0x36u, 0xB8u, 0x0Au, 0x68u, 0xE8u, 0xCEu, 0x17u, 0xE3u,
            0x03u, 0xB9u, 0x8Du, 0x39u, 0x3Bu, 0xD2u, 0x96u, 0xB8u, 0x49u, 0x1Cu, 0x1Du, 0x60u, 0x9Au, 0x81u, 0xBEu,
            0x07u, 0x0Fu, 0x09u, 0xB8u, 0xCAu, 0x3Fu, 0xD7u, 0xF7u, 0x0Du, 0x51u, 0xB0u, 0xD8u, 0x93u, 0x0Bu, 0x9Cu,
            0xD9u, 0xA5u, 0xE7u, 0x41u, 0x4Fu, 0x91u, 0x00u, 0xF8u, 0xCBu, 0xAEu, 0x95u, 0x43u, 0x53u, 0xF4u, 0x25u,
            0xD6u, 0x13u, 0x0Fu, 0x65u, 0x13u, 0xC0u, 0x9Bu, 0x71u, 0xC5u, 0xBCu, 0x41u, 0xFEu, 0x90u, 0x34u, 0xAFu,
            0x2Du, 0x29u, 0x2Bu, 0xE3u, 0xDBu, 0x69u, 0x92u, 0xD7u, 0x80u, 0x85u, 0x46u, 0x7Eu, 0xF9u, 0x9Au, 0x13u,
            0x66u, 0x99u, 0xC1u, 0x98u, 0x22u, 0xCDu, 0x24u, 0x0Eu, 0xE8u, 0xEAu, 0xC4u, 0x87u, 0xF3u, 0xB9u, 0x46u,
            0x7Cu, 0xBCu, 0xCFu, 0xD3u, 0x43u, 0x2Fu, 0x50u, 0x07u, 0xA3u, 0x25u, 0x84u, 0x3Du, 0x7Fu, 0x93u, 0xECu,
            0x17u, 0x3Bu, 0x3Eu, 0x24u, 0x9Eu, 0xDEu, 0x40u, 0xDAu, 0x0Au, 0xE7u, 0x66u, 0x9Bu, 0x20u, 0x2Au, 0x56u,
            0x0Du, 0x03u, 0x1Cu, 0x2Eu, 0xA0u, 0x55u, 0x63u, 0xDBu, 0x89u, 0xD5u, 0x8Cu, 0x9Cu, 0xE1u, 0x95u, 0xDEu,
            0x46u, 0x06u, 0xDDu, 0x6Du, 0x1Cu, 0x1Au, 0xDEu, 0x02u, 0x57u, 0x88u, 0xB6u, 0x94u, 0x90u, 0xBDu, 0xCFu,
            0x24u, 0xC4u, 0x4Fu, 0xA3u, 0x57u, 0xD3u, 0x29u, 0xEBu, 0x08u, 0xFEu, 0x4Cu, 0xE5u, 0x41u, 0x3Fu, 0xA3u,
            0xAAu};
        (void)IStdLib_MemCpy(encryptedPremasterSecret, encrypted_premaster_secret, encryptedPremasterSecretLen);
#else
        /* calculate encrypted pre master secret */
        /* RSA key was set by KeyM_SetCertificate in TcpIp_TlsParseCertificate */
        Std_Return = Csm_Encrypt(
            keyExchangeJobId,
            CRYPTO_OPERATIONMODE_SINGLECALL,
            context->preMasterSecret,
            context->masterSecretLen,
            encryptedPremasterSecret,
            &encryptedPremasterSecretLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }
#endif
        lengthFied = encryptedPremasterSecretLen + 2u;
    }
    else
    {
        /* todo: ECDHE */
        ret = TLS_ERR_INTERNAL_ERROR;
    }

    writePtr = context->outRecordContentStart;

    writePtr[0u] = TLS_HS_TYPE_CLIENT_KEY_EXCHANGE;
    writePtr[1u] = (lengthFied >> 16u) & 0xffu;
    writePtr[2u] = (lengthFied >> 8u) & 0xffu;
    writePtr[3u] = lengthFied & 0xffu;
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    writePtr[0u] = (encryptedPremasterSecretLen >> 8u) & 0xffu;
    writePtr[1u] = encryptedPremasterSecretLen & 0xffu;
    writePtr += 2u;

    (void)IStdLib_MemCpy(writePtr, encryptedPremasterSecret, encryptedPremasterSecretLen);
    writePtr += encryptedPremasterSecretLen;

    context->outRecordContentLength = writePtr - context->outRecordContentStart;
    context->outRecordContentType   = TLS_MSG_TYPE_HANDSHAKE;
    TcpIp_TlsBuildRecordHeader(context);

    /* TLS_CLIENT_KEY_EXCHANGE -> TLS_CLIENT_CHANGE_CIPHER_SPEC */
    tlsSocketPtr->socketTlsContext.state = TLS_CLIENT_CHANGE_CIPHER_SPEC;

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
        (void)IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;
#endif

        ret = TLS_RETURN_OK;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseCertificateVerify(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32      ret     = TLS_RETURN_OK;
    tlsContext* context = &tlsSocketPtr->socketTlsContext;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    ret = TcpIp_Tls13Decrypt(context);
    if (TLS_RETURN_OK != ret)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    /* todo: signature check */

#if (TLS_USE_CSM_API == STD_ON)
    Std_ReturnType Std_Return = TcpIp_TlsUpdateHSHash(context);
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

    /* TLS_SERVER_HELLO_DONE -> TLS_CLIENT_KEY_EXCHANGE */
    context->state = TLS_SERVER_FINISHED;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#if (STD_ON == TCPIP_TLS_SERVER_NAME_INDICATION)
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_TlsWriteServerHostName(uint8* serverName, uint8* bufPtr, uint32* olen)
{
    uint8*         msgPtr = bufPtr;
    const uint8*   end;
    uint32         hostname_len;
    Std_ReturnType Std_Return = E_NOT_OK;
    *olen                     = 0u;

    Std_Return   = E_OK;
    hostname_len = strlen(serverName);

    if ((end < msgPtr) || ((end - msgPtr) < (hostname_len + 9u)))
    {
        Std_Return = E_NOT_OK;
    }
    else
    {
        *msgPtr++ = (uint8)((TLS_EXT_SERVERNAME >> 8u) & 0xFFu);
        *msgPtr++ = (uint8)((TLS_EXT_SERVERNAME) & 0xFFu);
        *msgPtr++ = (uint8)(((hostname_len + 5u) >> 8u) & 0xFFu);
        *msgPtr++ = (uint8)(((hostname_len + 5u)) & 0xFFu);
        *msgPtr++ = (uint8)(((hostname_len + 3u) >> 8u) & 0xFFu);
        *msgPtr++ = (uint8)(((hostname_len + 3u)) & 0xFFu);
        *msgPtr++ = (uint8)((TLS_EXT_SERVERNAME_HOSTNAME) & 0xFFu);
        *msgPtr++ = (uint8)((hostname_len >> 8u) & 0xFFu);
        *msgPtr++ = (uint8)((hostname_len) & 0xFFu);
        (void)IStdLib_MemCpy(msgPtr, serverName, hostname_len);
        *olen = hostname_len + 9u;
    }

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#endif /* TCPIP_TLS_SERVER_NAME_INDICATION */

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsBuildCHExtensions(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** writePtrPtr)
{
    sint32         ret        = TLS_RETURN_OK;
    Std_ReturnType Std_Return = E_NOT_OK;
    uint8 *        writePtr = NULL_PTR, *extLenPtr = NULL_PTR;
    uint32         lengthFied      = 0u;
    uint16         recordSizeLimit = 2048u;
    tlsContext*    context         = &tlsSocketPtr->socketTlsContext;

    writePtr = *writePtrPtr;

    /* save extensions length ptr first */
    extLenPtr = writePtr;
    writePtr += 2u;

    /*********** start build extensions *****************/
    if (TRUE == context->supportTls13)
    {
        /* supported versions */
        lengthFied   = 5u;
        writePtr[0u] = (TLS_EXT_SUPPORTED_VERSIONS >> 8u) & 0xffu;
        writePtr[1u] = TLS_EXT_SUPPORTED_VERSIONS & 0xffu;
        writePtr[2u] = (lengthFied >> 8u) & 0xffu; /* type len */
        writePtr[3u] = lengthFied & 0xffu;

        writePtr[4u] = 4u; /* version len */

        writePtr[5u] = TLS_MAJOR_VERSION_3;
        writePtr[6u] = TLS_MINOR_VERSION_3;
        writePtr[7u] = TLS_MAJOR_VERSION_3;
        writePtr[8u] = TLS_MINOR_VERSION_4;
        writePtr += 9u;

        /* supported groups */
        lengthFied   = 2u;
        writePtr[0u] = (TLS_EXT_SUPPORTED_GROUPS >> 8u) & 0xffu;
        writePtr[1u] = TLS_EXT_SUPPORTED_GROUPS & 0xffu;
        writePtr[2u] = ((lengthFied + 2u) >> 8u) & 0xffu; /* type len */
        writePtr[3u] = (lengthFied + 2u) & 0xffu;
        writePtr[4u] = (lengthFied >> 8u) & 0xffu; /* group list len */
        writePtr[5u] = lengthFied & 0xffu;

        writePtr[6u] = (ECDHE_GROUP_X25519 >> 8u) & 0xffu;
        writePtr[7u] = ECDHE_GROUP_X25519 & 0xffu;
        writePtr += 8u;

        /* key share */
        uint8 dhPublicKey[32u] = {0u};
        lengthFied             = TLS_X25519_KEY_LEN;
        context->DHKeyLen      = TLS_X25519_KEY_LEN;
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
        Std_Return = Csm_KeyExchangeCalcPubVal(exchangeKeyId, dhPublicKey, &lengthFied);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_INTERNAL_ERROR;
        }

        writePtr[0u] = (TLS_EXT_KEY_SHARE >> 8u) & 0xffu;
        writePtr[1u] = TLS_EXT_KEY_SHARE & 0xffu;
        lengthFied   = 32u;
        writePtr[2u] = ((lengthFied + 6u) >> 8u) & 0xffu; /* type len */
        writePtr[3u] = (lengthFied + 6u) & 0xffu;
        writePtr[4u] = ((lengthFied + 4u) >> 8u) & 0xffu; /* key share len */
        writePtr[5u] = (lengthFied + 4u) & 0xffu;
        writePtr += 6u;

        writePtr[0u] = (ECDHE_GROUP_X25519 >> 8u) & 0xffu; /* key share entry */
        writePtr[1u] = ECDHE_GROUP_X25519 & 0xffu;
        writePtr[2u] = (lengthFied >> 8u) & 0xffu;
        writePtr[3u] = lengthFied & 0xffu;
        writePtr += 4u;
        (void)IStdLib_MemCpy(writePtr, dhPublicKey, lengthFied);
        writePtr += lengthFied;
    }

    /* record size limit */
    lengthFied   = 2u;
    writePtr[0u] = (TLS_EXT_RECORD_SIZE_LIMIT >> 8u) & 0xffu;
    writePtr[1u] = TLS_EXT_RECORD_SIZE_LIMIT & 0xffu;
    writePtr[2u] = (lengthFied >> 8u) & 0xffu;
    writePtr[3u] = lengthFied & 0xffu;
    writePtr[4u] = (recordSizeLimit >> 8u) & 0xffu;
    writePtr[5u] = recordSizeLimit & 0xffu;
    writePtr += 6u;

    /* signature algorithm */
    writePtr[0u] = (TLS_EXT_SIGNATURE_ALG >> 8u) & 0xffu;
    writePtr[1u] = TLS_EXT_SIGNATURE_ALG & 0xffu;
    lengthFied   = 4u;
    writePtr[2u] = (lengthFied >> 8u) & 0xffu;
    writePtr[3u] = lengthFied & 0xffu;
    lengthFied   = 2u; /* alg length */
    writePtr[4u] = (lengthFied >> 8u) & 0xffu;
    writePtr[5u] = lengthFied & 0xffu;
    writePtr[6u] = (TLS_SIG_ALG_RSA_PSS_SHA256 >> 8u) & 0xffu;
    writePtr[7u] = TLS_SIG_ALG_RSA_PSS_SHA256 & 0xffu;
    writePtr += 8u;
    /*************** extensions build end ***************/

    /* calculate and write extension len */
    lengthFied    = (uint32)(writePtr - extLenPtr - 2); /* PRQA S 4393 */ /* VL_TcpIp_4393 */
    extLenPtr[0u] = (lengthFied >> 8u) & 0xffu;
    extLenPtr[1u] = lengthFied & 0xffu;

    *writePtrPtr = writePtr;
    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsBuildClientHelloMessage(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    sint32         ret            = TLS_RETURN_OK;
    Std_ReturnType Std_Return     = E_NOT_OK;
    tlsContext*    context        = &tlsSocketPtr->socketTlsContext;
    uint32         lengthFied     = 0u;
    uint8*         writePtr       = NULL_PTR;
    uint8          ciphersuiteNum = context->connectionConfigPtr->CiphersuiteNum;

    writePtr = context->outRecordContentStart;

    /*	   Content
     *	   0  .   0   handshake type
     *	   1  .   3   handshake length
     *	   4  .   5   protocol version
     *	   6  .   9   UNIX time()
     *	  10  .  37   random bytes
     */
    writePtr[0u] = TLS_HS_TYPE_CLIENT_HELLO;
    /* skip handshake length first */
    writePtr += TLS_HANDSHAKE_HEADER_LENGTH;

    writePtr[0u] = TLS_MAJOR_VERSION_3;
    writePtr[1u] = TLS_MINOR_VERSION_3;
    writePtr += 2u;

    /* generate random */
    Std_Return = TcpIp_TlsGenerateRandomNumber(tlsSocketPtr);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }
    (void)IStdLib_MemCpy(writePtr, context->clientRandom, TLS_RANDOM_LENGTH);
    writePtr += TLS_RANDOM_LENGTH;

    /*	 38      .  38		session id length
     *	 39      . 39+n		session id
     *	40+n     . 41+n		ciphersuites length
     *	42+n     . 42+n+m	ciphersuites
     *	43+n+m   . 43+n+m	compression algs len
     *	44+n+m   . 44+n+m+l	compression algs
     *	44+n+m+l . 45+n+m+l	extensions length
     *	45+n+m+l . ..		extensions */

    /* session id length: 0 */
    writePtr[0u] = 0u;
    writePtr++;

    /* ciphersuites length */
    lengthFied   = (uint32)ciphersuiteNum << 1u; /* 2B per ciphersuite id */
    writePtr[0u] = (lengthFied >> 8u) & 0xffu;
    writePtr[1u] = lengthFied & 0xffu;
    writePtr += 2u;

    /* ciphersuites */
    const uint8* ciphersuiteIdList = context->connectionConfigPtr->CiphersuiteIdList;
    for (uint32 i = 0u; i < ciphersuiteNum; i++)
    {
        uint8 ciphersuiteIdListId = ciphersuiteIdList[i];
        if (TRUE == TcpIp_TlsCiphersuiteBusyStatus[ciphersuiteIdListId])
        {
            continue; /* PRQA S 0770 */ /* VL_TcpIp_0770 */
        }

        const TcpIp_TlsCiphersuiteDefinitionConfigType* ciphersuiteDefinitionPtr =
            &TcpIp_TlsCfgPtr->CiphersuiteDefinitionPtr[ciphersuiteIdListId];
        uint16 ciphersuiteId = ciphersuiteDefinitionPtr->CiphersuiteId;
        writePtr[0u]         = (ciphersuiteId >> 8u) & 0xffu;
        writePtr[1u]         = ciphersuiteId & 0xffu;
        writePtr += 2u;
        if (TLS_VERSION_V13 == ciphersuiteDefinitionPtr->Version)
        {
            /* Worker and Ciphersuite one-to-one corresponding relations, whilch measn they have same index */
            const TcpIp_TlsCiphersuiteWorkerConfigType* wokerPtr =
                &TcpIp_TlsCfgPtr->CiphersuiteWorkerPtr[ciphersuiteIdListId];
            const uint8* handshakeIdL = wokerPtr->HandshakeIdList;
            uint8        handshakeNum = wokerPtr->HandshakeNum;
            for (uint8 j = 0u; j < handshakeNum; j++)
            {
                uint8 handshakeIdListId = handshakeIdL[i];
                if (TRUE == TcpIp_TlsHandshakeBusyStatus[handshakeIdListId])
                {
                    continue; /* PRQA S 0770*/ /* VL_TcpIp_0770 */
                }

                context->handshakePtr = &TcpIp_TlsCfgPtr->HandshakePtr[handshakeIdListId];
                context->supportTls13 = TRUE;
            }
        }
    }

    /* compression algs */
    /* AUTOSAR dosen't support data compression */
    writePtr[0u] = 1u; /* compression filed length */
    writePtr[1u] = TLS_COMPRESS_NULL;
    writePtr += 2u;

    ret = TcpIp_TlsBuildCHExtensions(tlsSocketPtr, &writePtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

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
TCPIP_LOCAL sint32 TcpIp_TlsWriteClientHello(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    sint32         ret        = TLS_RETURN_OK;
    tlsContext*    context    = &tlsSocketPtr->socketTlsContext;

    ret = TcpIp_TlsBuildClientHelloMessage(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    /* TLS_CLIENT_HELLO -> TLS_SERVER_HELLO */
    tlsSocketPtr->socketTlsContext.state = TLS_SERVER_HELLO;
    context->minorVersion                = TLS_MINOR_VERSION_3;

    ret = TcpIp_TlsBioSendCallBack(tlsSocketPtr, context->outPBuf->payload, context->outTotalLen);
    if (ret > 0)
    {
#if (TLS_USE_CSM_API == STD_ON)
        uint32 hashJobId = context->handshakePtr->CsmHashVerifyJobId;

        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_START,
            context->outRecordContentStart,
            context->outRecordContentLength,
            context->handshakeMsgHash,
            &context->hashLen);
        if (TLS_RETURN_OK != Std_Return)
        {
            return TLS_ERR_CSM_HASH_ERROR;
        }

        Std_Return = Csm_Hash(
            hashJobId,
            CRYPTO_OPERATIONMODE_UPDATE,
            context->outRecordContentStart,
            context->outRecordContentLength,
            context->handshakeMsgHash,
            &context->hashLen);
        if (E_OK != Std_Return)
        {
            return TLS_ERR_CSM_HASH_ERROR;
        }
#else
        (void)IStdLib_MemCpy(
            &context->handshake_messages[context->handshake_messagesLen],
            context->outRecordContentStart,
            context->outRecordContentLength);
        context->handshake_messagesLen += context->outRecordContentLength;
#endif
        ret = TLS_ERR_SSL_WANT_READ;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsParseServerHello(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    Std_ReturnType Std_Return           = E_NOT_OK;
    sint32         ret                  = TLS_RETURN_OK;
    uint8          compressionMethodLen = 0u;
    uint8*         parsePtr             = NULL;
    uint16         SHCiphersuiteId      = 0u;
    tlsContext*    context              = &tlsSocketPtr->socketTlsContext;

    ret = TcpIp_TlsGetNextRecord(tlsSocketPtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    if (TLS_MSG_TYPE_HANDSHAKE != context->inRecordContentType)
    {
        return TLS_ERR_BAD_HS_SERVER_HELLO;
    }

    /*  we only check version of server hello, version of later record not checked anymore
        this field of TLS 1.3 is also 0x0303, for compatibility of old network devices
        TLS version select step:
        1. select ciphersuite in list, then version is confirmed(ciphersuites of TLS 1.2/1.3 are independent)
        2. for TLS 1.3, when we parse supported versions extensions, check if version is matched
    */
    ret = TcpIp_TlsVersionCheck(context);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

    parsePtr = context->inRecordContentStart;

    /* handshake type check */
    if (TLS_HS_TYPE_SERVER_HELLO != parsePtr[0u])
    {
        return TLS_ERR_BAD_HS_SERVER_HELLO;
    }
    /* skip length/version */
    parsePtr += 6u;

    (void)IStdLib_MemCpy(context->serverRandom, parsePtr, TLS_RANDOM_LENGTH);
    parsePtr += TLS_RANDOM_LENGTH;

    context->sessionIdLen = parsePtr[0u];
    parsePtr++;
    if (context->sessionIdLen > 0u)
    {
        (void)IStdLib_MemCpy(context->sessionId, parsePtr, context->sessionIdLen);
        parsePtr += context->sessionIdLen;
    }

    /* check if ciphersuite of server hello is in supported list */
    SHCiphersuiteId = (parsePtr[0u] << 8u) | parsePtr[1u];
    ret             = TcpIp_TlsCiphersuiteSelectInner(context, SHCiphersuiteId);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }
    parsePtr += 2u;

    /* AUTOSAR dosen't support data compression */
    compressionMethodLen = parsePtr[0u];
    parsePtr += compressionMethodLen + 1u;

    /* parse extension field */
    ret = TcpIp_TlsParseExtensions(tlsSocketPtr, parsePtr);
    if (TLS_RETURN_OK != ret)
    {
        return ret;
    }

#if (TLS_USE_CSM_API == STD_ON)
    uint32 hashJobId = context->handshakePtr->CsmHashVerifyJobId;
    uint32 resultLen = 0u;
    Std_Return       = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_START,
        context->outRecordContentStart,
        context->outRecordContentLength,
        context->handshakeMsgHash,
        &resultLen);
    if (E_OK != Std_Return)
    {
        return TLS_ERR_INTERNAL_ERROR;
    }

    Std_Return = Csm_Hash(
        hashJobId,
        CRYPTO_OPERATIONMODE_UPDATE,
        context->outRecordContentStart,
        context->outRecordContentLength,
        context->handshakeMsgHash,
        &resultLen);
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

    if (TLS_MINOR_VERSION_4 == context->minorVersion)
    {
        /* we can now caculate all secrets for handshake
         * TLS 1.3 encrypts some data in handshake, like encrypted Extension
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
sint32 TcpIp_TlsClientHandshakeStep(TcpIp_TlsSocketDataType* tlsSocketPtr)
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
     *  ==> ClientHello
     */
    case TLS_CLIENT_HELLO:
        ret = TcpIp_TlsWriteClientHello(tlsSocketPtr);
        break;

    /*
     *  <==   ServerHello
     * 	   Certificate
     * 	 ( ServerKeyExchange  )
     * 	 ( CertificateRequest )
     * 	   ServerHelloDone
     */
    case TLS_SERVER_HELLO:
        ret = TcpIp_TlsParseServerHello(tlsSocketPtr);
        break;

    case TLS_SERVER_CERTIFICATE:
        ret = TcpIp_TlsParseCertificate(tlsSocketPtr);
        break;

    case TLS_SERVER_KEY_EXCHANGE: /* if RSA key exchange then do nothing */
        ret = TcpIp_TlsParseServerKeyExchange(tlsSocketPtr);
        break;

    case TLS_CERTIFICATE_REQUEST: /* server request client certificate for bidirectional authentication */
        ret = TcpIp_TlsParseCertificateRequest(tlsSocketPtr);
        break;

    case TLS_SERVER_HELLO_DONE:
        ret = TcpIp_TlsParseServerHelloDone(tlsSocketPtr);
        break;

    /* ==> ( Certificate/Alert  )
     * 	   ClientKeyExchange
     * 	 ( CertificateVerify  )
     * 	   ChangeCipherSpec
     * 	   Finished 		  */
    case TLS_CLIENT_CERTIFICATE:
        ret = TcpIp_TlsWriteCertificate(tlsSocketPtr);
        break;

    case TLS_CLIENT_KEY_EXCHANGE:
        ret = TcpIp_TlsWriteClientKeyExchange(tlsSocketPtr);
        break;

    case TLS_CERTIFICATE_VERIFY:
        ret = TcpIp_TlsParseCertificateVerify(tlsSocketPtr);
        break;

    case TLS_CLIENT_CHANGE_CIPHER_SPEC:
        ret = TcpIp_TLsWriteChangeCipherSpec(tlsSocketPtr);
        break;

    case TLS_ENCRYPTED_EXTENSIONS:
        ret = TcpIp_TlsParseEncryptedExt(tlsSocketPtr);
        break;

    case TLS_CLIENT_FINISHED:
        ret = TcpIp_TlsWriteHandshakeFinished(tlsSocketPtr);
        break;

    /* <==   ( NewSessionTicket )
     * 	   ChangeCipherSpec
     * 	   Finished 		 */
    case TLS_SERVER_CHANGE_CIPHER_SPEC:
        ret = TcpIp_TlsParseChangeCipherSpec(tlsSocketPtr);
        break;

    case TLS_SERVER_FINISHED:
        ret = TcpIp_TlsParseHandshakeFinished(tlsSocketPtr);
        break;

    case TLS_FLUSH_BUFFERS: /* handshake done */
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
