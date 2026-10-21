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
 **  @file               : TcpIp_Tls.h
 **  @author             : pengfei.zhu
 **  @date               :
 **  @vendor             : isoft
 **  @description        : function declaration of TLS
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

/*******************************************************************************
**                      Include Section                                       **
*******************************************************************************/

#ifndef TCPIP_TLS_H
#define TCPIP_TLS_H
#include "TcpIp_Cfg.h"

#if (STD_ON == TCPIP_TCP_TLS_ENABLED)
#include "TcpIp_Internal.h"
#include "TcpIp.h"
#include "TcpIp_TlsTypes.h"
#include "KeyM.h"
#include "TcpIp_PBcfg.h"
#include "TcpIp_CfgTypes.h"

/*************************Function Declaration***********************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Initialize TLS module internal structures (free list, hash tables, etc.).
 *
 * @param tlsCfgPtr TLS post-build configuration pointer.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
void TcpIp_TlsInit(const TcpIp_TlsConfigType* tlsCfgPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief De-initialize TLS runtime for a socket and return to free list.
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
void TcpIp_TlsSocketDeInit(TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Build TLS record header for the current outgoing record.
 *
 * @param[in,out] context TLS context (uses outRecordContentLength/Type, updates outTotalLen and seqNum).
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
void TcpIp_TlsBuildRecordHeader(tlsContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Match by static address and bind a TLS connection configuration, then initialize it.
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @param staticAddrPtr   Static peer address and port.
 * @param connType        Connection type (server/client).
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
void TcpIp_TlsBaseStaticConnect(
    TcpIp_SocketRuntimeType*         sockeRuntimePtr,
    const TcpIp_SockAddrType*        staticAddrPtr,
    TcpIp_TlsConnectionInitStateType connType);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Process all TLS socket runtime nodes in the queue until empty.
 *
 * @param partitionIndex Partition index (unused).
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
void TcpIp_TlsSockeRuntimeProcess(ApplicationType partitionIndex);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		tls server state machine process.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 * Based on the return value and the Context->state status, determine how to proceed next
 * Generally two situations: reading and writing.
 * After reading the data, it is parsed and moves to the next state.
 * If the next state is "write", then the process continues within the loop.
 * If the next state is "read", then return TLS_ERR_SSL_WANT_READ and wait for the next message.
 */
sint32 TcpIp_TlsServerHandshakeStep(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Build and write certificate packet.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       tls error code.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsWriteCertificate(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Build and send change cipher spec packet.
 * @param[in]    context   : TLS context pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TLsWriteChangeCipherSpec(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Drive the TLS handshake state machine until completion or a non-OK result.
 *
 * @param[in,out] tlsSocketPtr TLS socket pointer.
 * @return TLS_RETURN_OK on completion; TLS_ERR_SSL_WANT_READ/WRITE to retry; negative on error.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsHandshakeStart(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		tls client state machine process.
 * @param[in]	tlsSocketPtr   : TLS socket pointer.
 * @return		tls error code.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace None
 *
 * Based on the return value and the Context->state status, determine how to proceed next
 * Generally two situations: reading and writing.
 * After reading the data, it is parsed and moves to the next state.
 * If the next state is "write", then the process continues within the loop.
 * If the next state is "read", then return TLS_ERR_SSL_WANT_READ and wait for the next message.
 */
sint32 TcpIp_TlsClientHandshakeStep(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief       Parse certificate.
 * @param[in]   tlsSocketPtr   : TLS socket pointer.
 * @return      tls error code.
 * @reentrant   TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsParseCertificate(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief       Parse Change Cipher Spec packet.
 * @param[in]   tlsSocketPtr   : TLS socket pointer.
 * @return      Std_ReturnType.
 * @reentrant   TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsParseChangeCipherSpec(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Write handshake finished (dispatches to TLS 1.2/1.3 variant).
 *
 * @param[in] tlsSocketPtr TLS socket pointer.
 * @return Std_ReturnType.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsWriteHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Parse Handshake Finished packet.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsParseHandshakeFinished(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        TLS buffer alloc and set up.
 * @param[in]    socketTlsContext   : TLS context pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsBufSetup(tlsContext* socketTlsContext);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Wrap up handshake messages.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsHandshakeWrapUp(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Read the next TLS record payload into the input buffer.
 *
 * @param[in] tlsSocketPtr TLS socket pointer.
 * @return TLS_RETURN_OK when full record is present; TLS_ERR_SSL_WANT_READ if partial; error code otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsGetNextRecord(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Decrypt and for TLS 1.3.
 * @param[in]    context   : TLS context pointer.
 * @return       tls error code.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * AEADEncrypted = AEAD-Encrypt(write_key, nonce, additional_data, plaintext)
 * @implement None
 * @range None
 */
sint32 TcpIp_Tls13Decrypt(tlsContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Decrypt data for TLS 1.2 and notify upper layer.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       tls error code.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_Tls12DecryptNotifyRecord(TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Decrypt and for TLS 1.3 and notify upper layer.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       tls error code.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_Tls13DecryptNotifyRecord(TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief TLS BIO send callback that writes data into TCP.
 *
 * @param tlsSocketPtr TLS socket runtime pointer.
 * @param dataptr      Data buffer to send.
 * @param dataLen      Length of data in bytes.
 * @return Bytes written on success; negative TLS error code on failure.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsBioSendCallBack(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* dataptr, uint16 dataLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief       Check if version is valid.
 * @param[in]   context   : TLS context.
 * @return      tls error code.
 * @reentrant   TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsVersionCheck(tlsContext* context);
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
sint32 TcpIp_TlsCiphersuiteSelect(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8** parsePtr);
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
sint32 TcpIp_TlsCiphersuiteSelectInner(tlsContext* context, uint16 chCiphersuiteId);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief       Parse extensions in hello message.
 * @param[in]   tlsSocketPtr   : TLS socket pointer.
 *             parsePtr: pointer to data.
 * @return      tls error code.
 * @reentrant   TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
sint32 TcpIp_TlsParseExtensions(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* parsePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief TLS BIO receive callback, copies from pbuf chain and advances read position.
 *
 * @param tlsSocketPtr TLS socket runtime pointer.
 * @param buf          Destination buffer.
 * @param len          Max bytes to copy.
 * @return Number of bytes copied.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
uint16 TcpIp_TlsBioRecvCallBack(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* buf, uint16 len);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Generate TLS Random (client/server) and optionally set first 4 bytes to UTC timestamp.
 *
 * @param[in,out] tlsSocketPtr TLS socket pointer.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_TlsGenerateRandomNumber(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Generate random bytes via CSM interface.
 *
 * @param resultPtr        Output random buffer.
 * @param resultLengthPtr  In/Out: requested length and actual generated length.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_TlsCsmRandomGenerate(uint8* resultPtr, uint32* resultLengthPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Encrypt and send data for TLS 1.2.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 * @return       tls error code.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_Tls12EncryptWriteRecord(
    TcpIp_TlsSocketDataType* tlsSocketPtr,
    const uint8*             plainTextPtr,
    uint16                   plainTextLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Encrypt and send data for TLS 1.3.
 * @param[in]    tlsSocketPtr   : TLS socket pointer.
 *             plainTextPtr   : plain text data.
 *             plainTextLen   : plain text data length.
 * @return       tls error code.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_Tls13EncryptWriteRecord(
    TcpIp_TlsSocketDataType* tlsSocketPtr,
    const uint8*             plainTextPtr,
    uint16                   plainTextLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Derive and store session secret to TlsCsmMasterSecretKeyRef.
 * @param[in]    context   : TLS context pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_TlsMasterSecretDerive(tlsContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief        Calculate TLS 1.2 write key.
 * @param[in]    context   : TLS context pointer.
 * @return       Std_ReturnType.
 * @reentrant    TRUE
 * @synchronous  TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_Tls12WriteKeyCalculation(tlsContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Update handshake running hash with the last outgoing handshake fragment.
 *
 * @param[in,out] context TLS context.
 * @retval E_OK     Update success
 * @retval E_NOT_OK Failure
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_TlsUpdateHSHash(tlsContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Derive TLS 1.3 handshake secrets (keys, IVs, finished key) per RFC 8446.
 *
 * @param[in,out] context TLS context.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_Tls13HSSecretDerive(tlsContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Report received bytes to TCP stack after TLS handshake is done.
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @param len             Number of bytes to report.
 * @return E_OK on success; E_NOT_OK if handshake not completed or on error.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_TlsRecved(const TcpIp_SocketRuntimeType* sockeRuntimePtr, uint16 len);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Dynamically bind a TLS connection configuration to a socket and initialize it.
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @param tlsConnetId     Connection configuration index.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_TlsBaseDynamicConnect(TcpIp_SocketRuntimeType* sockeRuntimePtr, uint16 tlsConnetId);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief HKDF-Extract as defined in RFC 5869.
 *
 * PRK = HMAC-Hash(salt, IKM)
 *
 * @param[in]  context TLS context.
 * @param[in]  salt    Optional salt buffer (can be zeroed if not used).
 * @param[in]  saltLen Length of salt.
 * @param[in]  IKM     Input keying material.
 * @param[in]  IKMLen  Length of IKM.
 * @param[out] PRK     Output pseudorandom key.
 * @param[in,out] PRKLenPtr In: buffer size; Out: PRK length.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_HKDFExtract(
    tlsContext*  context,
    const uint8* salt,
    uint32       saltLen,
    const uint8* IKM,
    uint32       IKMLen,
    uint8*       PRK,
    uint32*      PRKLenPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief HKDF-Expand-Label per TLS 1.3 (RFC 8446).
 *
 * result = HKDF-Expand(secret, HkdfLabel(label, input), resultLen)
 *
 * @param[in]  context    TLS context.
 * @param[in]  secret     Secret key for expansion.
 * @param[in]  secretLen  Length of secret.
 * @param[in]  label      TLS 1.3 label string (without "tls13 ").
 * @param[in]  labelLen   Length of label.
 * @param[in]  input      Context/input bytes (e.g., transcript hash).
 * @param[in]  inputLen   Length of input bytes.
 * @param[out] result     Output keying material.
 * @param[in]  resultLen  Desired length of result.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_HKDFExpandLabel(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* label,
    uint32       labelLen,
    const uint8* input,
    uint16       inputLen,
    uint8*       result,
    uint16       resultLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief TLS 1.3 Derive-Secret helper per RFC 8446.
 *
 * result = HKDF-Expand-Label(secret, label, Hash(messages), Hash.length)
 *
 * @param[in]  context      TLS context.
 * @param[in]  secret       Base secret.
 * @param[in]  secretLen    Length of base secret.
 * @param[in]  label        TLS label string (e.g. "derived").
 * @param[in]  labelLen     Length of label string.
 * @param[in]  messages     Transcript hash input buffer.
 * @param[in]  messagesLen  Length of messages buffer.
 * @param[out] result       Output derived secret (hash length).
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_DeriveSecret(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* label,
    uint32       labelLen,
    const uint8* messages,
    uint32       messagesLen,
    uint8*       result);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief TLS 1.2 PRF function using label and seed.
 *
 * result = PRF(secret, label, seed, resultLen)
 *
 * @param[in]  context    TLS context.
 * @param[in]  secret     Secret input to PRF.
 * @param[in]  secretLen  Length of secret.
 * @param[in]  label      Label string bytes.
 * @param[in]  labelLen   Length of label.
 * @param[in]  seed       Seed bytes (often randoms).
 * @param[in]  seedLen    Length of seed.
 * @param[out] result     Output buffer for PRF bytes.
 * @param[in]  resultLen  Number of bytes to generate.
 * @return E_OK on success; E_NOT_OK otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
Std_ReturnType TcpIp_TlsPRF(
    tlsContext*  context,
    const uint8* secret,
    uint32       secretLen,
    const uint8* label,
    uint32       labelLen,
    const uint8* seed,
    uint32       seedLen,
    uint8*       result,
    uint32       resultLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Initiate TCP connection and register TLS connected callback.
 *
 * @param tpcb   TCP PCB.
 * @param ipaddr Remote IP address.
 * @param port   Remote port.
 * @return LwIP error code.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
err_t TcpIp_TlsConnet(struct tcp_pcb* tpcb, ip_addr_t* ipaddr, uint16 port);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Send application data: segment, encrypt and write TLS records (TLS 1.2/1.3).
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @param dataptr         Plaintext data pointer.
 * @param len             Plaintext data length in bytes.
 * @return ERR_OK on success; ERR_VAL on failure.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
err_t TcpIp_TlsHandleTxAppData(const TcpIp_SocketRuntimeType* sockeRuntimePtr, const uint8* dataptr, uint16 len);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_Xor(uint32 len, const uint8* a1, const uint8* a2, uint8* des);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/********************************************************************************************/

#endif /* STD_ON == TCPIP_TCP_TLS_ENABLED */
#endif /*TCPIP_TLS_H*/
