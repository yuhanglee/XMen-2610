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
 **  @file               : TcpIp_Ike_Types.h
 **  @author             : xiankun.zhou
 **  @date               : 2025/07/28
 **  @vendor             : isoft
 **  @description        : IKE callback function header
 **
 ***********************************************************************************************************************/

#ifndef TCPIP_IKE_TYPES_H_
#define TCPIP_IKE_TYPES_H_

/* =================================================== inclusions =================================================== */

#include "TcpIp_Types.h"
#include "lwip/ipsec.h"
#if (STD_ON == TCPIP_IPSEC_ENABLED)
/* ================================================ type definitions ================================================ */
#define IKE_IKE_SPI_LEN        8u
#define IKE_HEADER_LEN         28u
#define IKE_PAYLOAD_HEADER_LEN 4u
#define IKE_NONCE_LEN          32u
#define IKE_IV_LEN             16u

#define IKE_DH_KEY_MAX_LEN    64u
#define IKE_PRF_KEY_MAX_LEN   64u
#define IKE_ENCR_KEY_MAX_LEN  32u
#define IKE_INTEG_KEY_MAX_LEN 64u
#define IKE_AUTH_KEY_MAX_LEN  256u
typedef struct
{
    /* SPD data */
    TcpIp_IpSecPolicyType PolicyType;
    TcpIp_IpSecHeaderType HeaderType;
    uint8                 Protocol;
    uint16                RemPortRangeStart;
    uint16                RemPortRangeEnd;
    uint16                LocalPortRangeStart;
    uint16                LocalPortRangeEnd;
    uint32                LocalIpAddrStart;
    uint32                LocalIpAddrEnd;
    uint32                RemIpAddrStart;
    uint32                RemIpAddrEnd;

    /* SAD data */
    uint32              InboundSpi;
    uint32              OutboundSpi;
    uint32              InboundSeqNum;
    uint32              OutboundSeqNum;
    uint8               IntegrityTransformJobPairId;
    uint8               EncryptionTransformJobPairId;
    TcpIp_IpSecModeType Mode;
    boolean             Active;
} TcpIp_IkeSAType;

typedef struct IkeConnContextTag
{
    uint8              InitiatorSPI[IKE_IKE_SPI_LEN];
    uint8              ResponderSPI[IKE_IKE_SPI_LEN];
    uint8              InitiatorNonce[IKE_NONCE_LEN];
    uint8              ResponderNonce[IKE_NONCE_LEN];
    uint32             ResponderNonceLen;
    uint32             macedIDLen;
    IkeConnStatusType  ConnStatus;
    TcpIp_SocketIdType SocketId;
    uint8              RetransmitTries;
    uint32             RetransmitTimeoutMs;
    uint32             RetransmitRemainTick;
    uint32             MessageId;
    uint32             PeerMessageId;
    uint8              InitiatorSignedOctets[1024];
    uint32             RealMessage1Len;

    /* IKE_Config.Transforms->EncrTransform index */
    uint32 EncrTransformPbCfgId;
    uint32 PrfTransformPbCfgId;
    uint32 IntegTransformPbCfgId;
    uint32 DhTransformPbCfgId;

    /* key information */
    uint8 DHKey[IKE_DH_KEY_MAX_LEN];
    uint8 DHKeyLen;
    uint8 SKEYSEED[IKE_PRF_KEY_MAX_LEN];
    uint8 SK_d[IKE_PRF_KEY_MAX_LEN];
    uint8 SK_pi[IKE_PRF_KEY_MAX_LEN];
    uint8 SK_pr[IKE_PRF_KEY_MAX_LEN];
    uint8 PrfKeyLen; /* length of SKEYSEED SK_d SK_pi SK_pr */
    uint8 SK_ai[IKE_INTEG_KEY_MAX_LEN];
    uint8 SK_ar[IKE_INTEG_KEY_MAX_LEN];
    uint8 IntegKeyLen;
    uint8 IntegOutputLen;
    uint8 SK_ei[IKE_ENCR_KEY_MAX_LEN];
    uint8 SK_er[IKE_ENCR_KEY_MAX_LEN];
    uint8 EncrKeyLen;
    uint8 IV[IKE_IV_LEN]; /* fixed IV len for ENCR_AES_CBC */

    /* incoming data */
    struct pbuf* inPBuf;
    uint8*       inBufPtr;
    uint16       inContentLength;

    /* outgoing data */
    struct pbuf* outPBuf;
    uint8*       outBufPtr;
    uint32       outContentLength;

    uint16 SABitMap; /* bitmap refer to SadSpdList; length related to TCPIP_MAX_SA_NUMBER */
} IkeConnContext;

typedef struct Ike_RxRuntimeTag
{
    TcpIp_SocketIdType        SocketId;
    const TcpIp_SockAddrType* RemoteAddrPtr;
    const uint8*              BufPtr;
    uint16                    Length;
    boolean                   Active;
    struct Ike_RxRuntimeTag*  Next;
} Ike_RxRuntimeType;

/* ========================================= external function declarations ========================================= */

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief         The TCP/IP stack calls this primitive after the reception of data on a socket. The socket identifier
 *                along with configuration information determines which module is to be called.
 *
 * @param[in]     SocketId: Socket identifier of the related local socket resource.
 * @param[in]     RemoteAddrPtr: Pointer to memory containing IP address and port of the
 * @param[in]     BufPtr: Pointer to the received data
 * @param[in]     Length: Data length of the received TCP segment or UDP datagram
 * @reentrant     Reentrant for different SocketIds. Non reentrant for the same SocketId.
 * @synchronous   TRUE
 * @trace         CPD-74648
 */
void TcpIp_IkeRxIndication(
    TcpIp_SocketIdType        SocketId,
    const TcpIp_SockAddrType* RemoteAddrPtr,
    const uint8*              BufPtr,
    uint16                    Length);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#endif /* TCPIP_IPSEC_ENABLED */

#endif /* TCPIP_IKE_TYPES_H_ */
