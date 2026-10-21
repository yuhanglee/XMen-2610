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
 **  @file               : TcpIp_TlsBase.c
 **  @author             : darren.zhang
 **  @date               : 2018/02/21
 **  @vendor             : isoft
 **  @description        : TLS basic API implementations
 **
 ***********************************************************************************************************************/

/***********************************************************************************************************************
**                                          REVISION   HISTORY                                                        **
***********************************************************************************************************************/
/* <VERSION>    <DATE>       <AUTHOR>        <REVISION LOG>
 *  V2.0.0    [20200828]  [pengfei.zhu]   Update to R19-11.
 *  V2.0.1    [20200928]  [pengfei.zhu]   QAC test.
 *  V2.1.0    [20210123]  [darren.zhang]  Code refactoring
 *  V2.2.0    [20250612]  [xiankun.zhou]  Code refactoring
 **********************************************************************************************************************/
/* PRQA S 2889 EOF */       /* VL_QAC_MultiReturn */
/* PRQA S 1881, 2144 EOF */ /* VL_TcpIp_1881, VL_TcpIp_2144 */
/* PRQA S 0686 EOF */       /* VL_TcpIp_0686 */
/* PRQA S 4115 EOF */       /* VL_TcpIp_4115 */
/* PRQA S 0316 EOF */       /* VL_TcpIp_0316 */
/* PRQA S 2981 EOF */       /* VL_TcpIp_2981 */
/* PRQA S 0317 EOF */       /* VL_TcpIp_0317 */
/* PRQA S 0488, 0317 EOF */ /* VL_TcpIp_0488, VL_TcpIp_0317 */
/* PRQA S 3200 EOF */       /* VL_TcpIp_3200 */
/* PRQA S 2981, 2053 EOF */ /* VL_TcpIp_2053 */
/* PRQA S 4115, 3344 EOF */ /* VL_TcpIp_2053 */
/* PRQA S 1258 EOF */       /* VL_TcpIp_1258 */
/* PRQA S 1277 EOF */       /* VL_TcpIp_1277 */
/* PRQA S 3673, 3678 EOF */ /* VL_TcpIp_3673, VL_TcpIp_3678 */
/* PRQA S 0553 EOF */       /* VL_QAC_UnUsedFiles */
#include "TcpIp_Cfg.h"

#if (STD_ON == TCPIP_TCP_TLS_ENABLED)
#include "Std_Types.h"
#include "TcpIp_Tls.h"
#include "TcpIp_Cfg.h"
#include "TcpIp_Types.h"
#include "SchM_TcpIp.h"
#include "TcpIp_PBcfg.h"
#include "Csm.h"

/* inner function condtion check level,per level consume memory or cycles is different */
#if !defined(TCPIP_TLS_CHECK_TAG)
#define TCPIP_TLS_CHECK
#define TCPIP_TLS_CHECK_OUTPUT(...) TCPIP_CHECK_OUTPUT(__VA_ARGS__)
#endif /* defined(TCPIP_INNER_CHECK_TAG) */
/***********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 ***********************************************************************************************************************/
#define U32FLAG_INDEX(id)       ((id) >> 5u)
#define U32FLAG_MASK(index)     (((uint32)0x1u) << ((index) & 0x1fu))
#define TLS_CONNGROUP_ARRY_SIZE ((TCPIP_TCP_TLS_CONNECTION_GROUP_NUM + 31u) >> 5u) /* (x+31)/32 */

#define TCP_TLS_WRITE_FLAG_COPY (0x01u)

#if defined(TCPIP_FASTTX_TCP)
#define TCPIP_TLS_FASTTX_TCP
#endif /* defined(TCPIP_FASTTX_TCP) */

/***********************************************************************************************************************
 *  LOCAL DATA
 ***********************************************************************************************************************/

#define TCPIP_START_SEC_VAR_CLEARED_PTR
#include "TcpIp_MemMap.h"
/**
 * @brief Global TLS configuration pointer (post-build config).
 *
 * Set once in TcpIp_TlsInit() and used by TLS code paths
 * to access static connection/ciphersuite/handshake settings.
 * @range None
 */
const TcpIp_TlsConfigType* TcpIp_TlsCfgPtr; /* PRQA S 3408 */ /* VL_TcpIp_3408 */
#define TCPIP_STOP_SEC_VAR_CLEARED_PTR
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/* each partition has an individual TlsSockeRuntimeHead pointer */
/**
 * @brief Per-partition head of the pending TLS socket runtime queue.
 *
 * Producer: TCP receive callback enqueues sockets for TLS processing.
 * Consumer: TcpIp_TlsSockeRuntimeProcess() drains and processes this queue.
 * @range None
 */
/* PRQA S 3408 ++ */ /* VL_TcpIp_3408 */
TCPIP_LOCAL TcpIp_SocketRuntimeType* TcpIp_TlsSockeRuntimeHead[TCPIP_PARTITION_NUMBER];
/* PRQA S 3408 -- */
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#if (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON)
#if (TCPIP_TLS_SERVER_CONN_STATIC_ASSIGN_NUMBER > 0u)
#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Storage for server-side TLS connection hash buckets.
 *
 * One bucket per statically assigned TLS server connection.
 * @range None
 */
TcpIp_TlsHashBucket TcpIp_TlsServerHashBucketArray[TCPIP_TLS_SERVER_CONN_STATIC_ASSIGN_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Server-side TLS connection hash table heads.
 *
 * Each entry points to a chain of buckets that match the hash index.
 * @range None
 */
TcpIp_TlsHashBucket* TcpIp_TlsServerHashTable[TCPIP_TLS_SERVER_HASH_TABLE_SIZE];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CONFIG_DATA_32
#include "TcpIp_MemMap.h"
extern const uint32 TcpIp_TlsServerNetMaskHash[];
#define TCPIP_STOP_SEC_CONFIG_DATA_32
#include "TcpIp_MemMap.h"
#endif

#if (TCPIP_TLS_CLIENT_CONN_STATIC_ASSIGN_NUMBER > 0u)
#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Storage for client-side TLS connection hash buckets.
 *
 * One bucket per statically assigned TLS client connection.
 * @range None
 */
TcpIp_TlsHashBucket TcpIp_TlsClientHashBucketArray[TCPIP_TLS_CLIENT_CONN_STATIC_ASSIGN_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Client-side TLS connection hash table heads.
 *
 * Each entry points to a chain of buckets that match the hash index.
 * @range None
 */
TcpIp_TlsHashBucket* TcpIp_TlsClientHashTable[TCPIP_TLS_CLIENT_HASH_TABLE_SIZE];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CONFIG_DATA_32
#include "TcpIp_MemMap.h"
extern const uint32 TcpIp_TlsClientNetMaskHash[];
#define TCPIP_STOP_SEC_CONFIG_DATA_32
#include "TcpIp_MemMap.h"
#endif
#endif

#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Connection group usage bitmap (bit-packed in uint32 elements).
 *
 * Managed via TLS_CONNGROUP_* macros to mark groups used/unused.
 * @range None
 */
TCPIP_LOCAL uint32 TcpIp_TlsConnectionGroupState[TLS_CONNGROUP_ARRY_SIZE];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TLS_CONNGROUP_IS_USED(conIndex) \
    ((TcpIp_TlsConnectionGroupState[U32FLAG_INDEX(conIndex)] & (U32FLAG_MASK(conIndex))) == U32FLAG_MASK(conIndex))
#define TLS_CONNGROUP_SET_USED(conIndex)                                                  \
    do                                                                                    \
    {                                                                                     \
        TcpIp_TlsConnectionGroupState[U32FLAG_INDEX(conIndex)] |= U32FLAG_MASK(conIndex); \
    } while (0u);
#define TLS_CONNGROUP_SET_UNUSED(conIndex)                                                           \
    do                                                                                               \
    {                                                                                                \
        TcpIp_TlsConnectionGroupState[U32FLAG_INDEX(conIndex)] &= (uint32)(~U32FLAG_MASK(conIndex)); \
    } while (0u);

#endif /* (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u) */

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Per-handshake worker busy flags.
 *
 * TRUE => handshake id is currently allocated and in use.
 * @range None
 */
/* PRQA S 3408 ++ */ /* VL_TcpIp_3408 */
boolean TcpIp_TlsHandshakeBusyStatus[TCPIP_TLS_HANDSHAKE_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Per-ciphersuite worker busy flags.
 *
 * TRUE => ciphersuite id is currently allocated and in use.
 * @range None
 */
boolean TcpIp_TlsCiphersuiteBusyStatus[TCPIP_TLS_CIPHERSUITE_NUMBER];
/* PRQA S 3408 -- */
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief Per-connection busy flags for TLS connections.
 *
 * TRUE => the static TLS connection entry is currently bound and active.
 * @range None
 */
TCPIP_LOCAL boolean TcpIp_TlsConnectionBusyStatus[TCPIP_TLS_CONNECTION_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_PTR
#include "TcpIp_MemMap.h"
/**
 * @brief Head of the TLS socket data free list (idle pool).
 * @range None
 */
TCPIP_LOCAL TcpIp_TlsSocketDataType* TcpIp_TlsSocketIdleListPtr;
#define TCPIP_STOP_SEC_VAR_CLEARED_PTR
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
/**
 * @brief TLS socket data pool; entries are linked via the 'next' field.
 * @range None
 */
/* PRQA S 3218++ */ /* VL_TcpIp_3218 */
TCPIP_LOCAL TcpIp_TlsSocketDataType TcpIp_TlsSocketDataTable[TCPIP_TLS_CONNECTION_NUMBER];
/* PRQA S 3218-- */ /* VL_TcpIp_3218 */
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

/***********************************************************************************************************************
 *  LOCAL FUNCTIONS PROTOTYPES
 ***********************************************************************************************************************/
#if (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON)
TCPIP_LOCAL inline uint32 TcpIp_TlsHash32Wang(uint32 key);

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsHashInsert(const TcpIp_TlsConnectionConfigType* ConnectionPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL const TcpIp_TlsConnectionConfigType*
    TcpIp_TlsHashLookup(uint32 ip, uint16 port, TcpIp_TlsConnectionInitStateType connType);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#endif

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsFreeContex(TcpIp_TlsSocketDataType* tlsSocketPtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief TCP connected callback; starts TLS handshake processing.
 *
 * @param arg  Context pointer (TcpIp_SocketRuntimeType).
 * @param tpcb TCP PCB.
 * @param err  LwIP error code.
 * @return LwIP error code, usually ERR_OK.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL err_t TcpIp_TlsConnected(void* arg, struct tcp_pcb* tpcb, err_t err);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/* PRQA S 3432 */ /* VL_TcpIp_3432 */

/*******************************************************************************
**                      Private Function Declarations                         **
*******************************************************************************/
/* Function prototype for tcp error callback functions. Called when the pcb receives a RST or is unexpectedly closed
for any other reason */
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief TCP error callback (RST or unexpected close).
 *
 * @param arg Context pointer (TcpIp_SocketRuntimeType).
 * @param err LwIP error code.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL void TcpIp_TlsErrCallBack(void* arg, err_t err);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Initialize TLS socket runtime and register TCP callbacks.
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @return E_OK on success; E_NOT_OK on failure.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL Std_ReturnType TcpIp_TlsSocketInit(TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Notify upper layer after TLS handshake is completed successfully.
 *        Also reports TCPIP_TLS_HANDSHAKE_SUCCEEDED event.
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL void TcpIp_TlsHandshakeDoneNotifyUpLayer(TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Handle receiving and decrypting of TLS application data.
 *        Dispatches to TLS 1.2 or 1.3 implementation.
 *
 * @param tpcb            TCP PCB.
 * @param sockeRuntimePtr Socket runtime pointer.
 * @return TLS_RETURN_OK on success; TLS_ERR_SSL_WANT_* for retry; negative on error.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL sint32 TcpIp_TlsHandleRxAppData(struct tcp_pcb* tpcb, TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Perform one TLS receive processing step (handshake or application data).
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @return LwIP error code (usually ERR_OK).
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL err_t TcpIp_TlsRecvProcess(TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Insert a TLS socket runtime node to the pending processing queue (tail insert).
 *
 * @param sockeRuntimePtr Socket runtime pointer.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL void TcpIp_TlsSockeRuntimeInsert(TcpIp_SocketRuntimeType* sockeRuntimePtr);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief TCP receive callback; queue data and trigger TLS processing.
 *
 * @param arg   Context pointer (TcpIp_SocketRuntimeType).
 * @param tpcb  TCP PCB.
 * @param pBuf  Received pbuf chain; NULL if peer sent FIN or on error.
 * @param err   LwIP error code.
 * @return LwIP error code, usually ERR_OK.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL err_t TcpIp_TlsRecvCallBack(void* arg, struct tcp_pcb* tpcb, struct pbuf* pBuf, err_t err);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/***********************************************************************************************************************
 *  LOCAL FUNCTIONS
 ***********************************************************************************************************************/
#if (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON)
/**
 * @brief 32-bit Wang hash used for TLS hash table indexing.
 *
 * @param key Input key (e.g., combined IP segment and port).
 * @return Mixed 32-bit hash value.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL inline uint32 TcpIp_TlsHash32Wang(uint32 key)
{
    key = ~key + (key << 15u); /* same as formula: key = (key << 15) - key - 1 */
    key = key ^ (key >> 12u);
    key = key + (key << 2u);
    key = key ^ (key >> 4u);
    key = key + (key << 3u) + (key << 11u);
    key = key ^ (key >> 16u);
    return key;
}

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Insert static TLS connection configurations into hash tables.
 *
 * Computes hash index from IP net segment and port, then inserts the
 * connection into either the server or client hash table.
 *
 * @param ConnectionPtr Pointer to the TLS connection configuration array.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL void TcpIp_TlsHashInsert(const TcpIp_TlsConnectionConfigType* ConnectionPtr)
{
    uint32               netSegment = 0u, hashBucketArrayIndex = 0u, hashKey = 0u, hashIndex = 0u;
    TcpIp_TlsHashBucket* bucketPtr = NULL_PTR;

    for (uint32 tlsConnetId = 0u; tlsConnetId < TCPIP_TLS_CONNECTION_NUMBER; tlsConnetId++, hashBucketArrayIndex++)
    {
        const TcpIp_TlsConnectionConfigType* TlsConnPtr = &ConnectionPtr[tlsConnetId];
        if (0u == TlsConnPtr->PortAssignment)
        {
            continue;
        }

        TcpIp_LocalAddrType* IpAddressPtr = TlsConnPtr->IpAddressAssignment;
        if (IpAddressPtr)
        {
            netSegment = *IpAddressPtr->IpAddrCfgPtr->StaticIpAddrPtr;
            if (IpAddressPtr->IpAddrCfgPtr->NetmaskPtr)
            {
                netSegment = netSegment & (*IpAddressPtr->IpAddrCfgPtr->NetmaskPtr);
            }
        }

        hashKey   = netSegment ^ (uint32)TlsConnPtr->PortAssignment;
        hashIndex = TcpIp_TlsHash32Wang(hashKey) % TCPIP_TLS_SERVER_HASH_TABLE_SIZE;

        /* insert hash table */
        switch (ConnectionPtr->ConnectionType)
        {
#if (TCPIP_TLS_SERVER_CONN_STATIC_ASSIGN_NUMBER > 0u)
        case TLS_SERVER:
            bucketPtr                           = &TcpIp_TlsServerHashBucketArray[hashBucketArrayIndex];
            bucketPtr->next                     = TcpIp_TlsServerHashTable[hashIndex];
            TcpIp_TlsServerHashTable[hashIndex] = bucketPtr;
            break;
#endif
#if (TCPIP_TLS_CLIENT_CONN_STATIC_ASSIGN_NUMBER > 0u)
        case TLS_CLIENT:
            bucketPtr                           = &TcpIp_TlsClientHashBucketArray[hashBucketArrayIndex];
            bucketPtr->next                     = TcpIp_TlsClientHashTable[hashIndex];
            TcpIp_TlsClientHashTable[hashIndex] = bucketPtr;
            break;
#endif
        default:
            continue;
        }

        bucketPtr->netSegment  = netSegment;
        bucketPtr->tlsCnCfgPtr = TlsConnPtr;
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief Lookup a TLS static connection configuration by IP and port.
 *
 * @param ip       Remote IP address (host order).
 * @param port     Port number (host order).
 * @param connType Connection type (server/client).
 * @return Pointer to connection configuration on success; NULL otherwise.
 * @reentrant TRUE
 * @synchronous TRUE
 * @trace None
 * @implement None
 * @range None
 */
TCPIP_LOCAL const TcpIp_TlsConnectionConfigType*
    TcpIp_TlsHashLookup(uint32 ip, uint16 port, TcpIp_TlsConnectionInitStateType connType)
{
    uint32 netSegment = 0u, hashKey = 0u, index = 0u;

    switch (connType)
    {
#if (TCPIP_TLS_SERVER_CONN_STATIC_ASSIGN_NUMBER > 0u)
    case TLS_SERVER:
        for (uint32 i = 0u; i < TCPIP_TLS_SERVER_CONN_MASK_NUMBER; i++)
        {
            netSegment = ip & TcpIp_TlsServerNetMaskHash[i];
            hashKey    = netSegment ^ (uint32)port;
            index      = TcpIp_TlsHash32Wang(hashKey) % TCPIP_TLS_SERVER_HASH_TABLE_SIZE;

            TcpIp_TlsHashBucket* bucketPtr = TcpIp_TlsServerHashTable[index];
            while (bucketPtr)
            {
                if ((bucketPtr->netSegment == netSegment) && (bucketPtr->tlsCnCfgPtr->PortAssignment == port)
                    && (FALSE == TcpIp_TlsConnectionBusyStatus[bucketPtr->tlsCnCfgPtr->ConnectionId]))
                {
                    return bucketPtr->tlsCnCfgPtr;
                }
                bucketPtr = bucketPtr->next;
            }
        }
        break;
#endif
#if (TCPIP_TLS_CLIENT_CONN_STATIC_ASSIGN_NUMBER > 0u)
    case TLS_CLIENT:
        for (uint32 i = 0u; i < TCPIP_TLS_CLIENT_CONN_MASK_NUMBER; i++)
        {
            netSegment = ip & TcpIp_TlsClientNetMaskHash[i];
            hashKey    = netSegment ^ (uint32)port;
            index      = TcpIp_TlsHash32Wang(hashKey) % TCPIP_TLS_CLIENT_HASH_TABLE_SIZE;

            TcpIp_TlsHashBucket* bucketPtr = TcpIp_TlsClientHashTable[index];
            while (bucketPtr)
            {
                if ((bucketPtr->netSegment == netSegment) && (bucketPtr->tlsCnCfgPtr->PortAssignment == port)
                    && (FALSE == TcpIp_TlsConnectionBusyStatus[bucketPtr->tlsCnCfgPtr->ConnectionId]))
                {
                    return bucketPtr->tlsCnCfgPtr;
                }
                bucketPtr = bucketPtr->next;
            }
        }
        break;
#endif
    default:
        break;
    }

    return NULL;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#endif /* (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON) */

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
sint32 TcpIp_TlsBioSendCallBack(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* dataptr, uint16 dataLen)
{
    sint32 written = 0;

    uint16          localdataLen = dataLen;
    struct tcp_pcb* curPcbPtr    = tlsSocketPtr->PcbPtr;

    while (localdataLen > 0u)
    {
        uint16 wrLen = localdataLen;
        SchM_Enter_TcpIp_ExclusiveArea_Tx();
        err_t err = (err_t)ERR_OK;
        err       = tcp_write(curPcbPtr, dataptr, wrLen, (u8_t)TCP_WRITE_FLAG_COPY);

        SchM_Exit_TcpIp_ExclusiveArea_Tx();

        if (err == ERR_OK)
        {
            written += (sint32)wrLen;
            localdataLen -= wrLen;
        }
        else
        {
            written = TLS_ERR_NET_SEND_FAILED;
            break;
        }
    }

    return written;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
uint16 TcpIp_TlsBioRecvCallBack(TcpIp_TlsSocketDataType* tlsSocketPtr, uint8* buf, uint16 len)
{
    uint16       bufRet = 0u, bufDecrease = 0u;
    struct pbuf* bufPtr = tlsSocketPtr->rx;

    /* copy data */
    bufRet      = pbuf_copy_partial(bufPtr, buf, len, 0u);
    bufDecrease = bufRet;
    tlsSocketPtr->bioBytesRead += bufRet;

    while (bufPtr && (bufDecrease >= bufPtr->len)) /* Maybe we read data from 1 more pbuf */
    {
        bufDecrease -= bufPtr->len;
        tlsSocketPtr->rx = bufPtr->next;
        bufPtr->next     = NULL;
        (void)pbuf_free(bufPtr);
        bufPtr = tlsSocketPtr->rx;
    }

    if ((NULL_PTR == bufPtr) || (0u == bufDecrease))
    {
        /* pbuf chain has been fully read */
        return bufRet;
    }

    /* hide the copied bytes from the pbuf */
    u8_t u8Ret = pbuf_remove_header(bufPtr, bufDecrease);

    return bufRet;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL err_t TcpIp_TlsRecvCallBack(void* arg, struct tcp_pcb* tpcb, struct pbuf* pBuf, err_t err)
{
    TCPIP_UNUSED_ARG(err);
    err_t                    ret             = (err_t)ERR_OK;
    TcpIp_SocketRuntimeType* sockeRuntimePtr = (TcpIp_SocketRuntimeType*)arg;

    TcpIp_TlsSocketDataType* tlsSocketPtr = sockeRuntimePtr->tlsPtr;
    struct pbuf*             pBufCloned   = pbuf_clone(PBUF_RAW, PBUF_POOL, pBuf);
    pbuf_free(pBuf);

    if (pBuf)
    {
        /* If we come here, the connection is in good state (handshake phase or application data phase).
        Queue up the pbuf for processing as handshake data or application data. */
        if (tlsSocketPtr->rx == NULL)
        {
            tlsSocketPtr->rx = pBufCloned;
        }
        else
        {
            pbuf_cat(tlsSocketPtr->rx, pBufCloned);
        }

        /* insert to job list, process in mainfunction*/
        TcpIp_TlsSockeRuntimeInsert(sockeRuntimePtr);
    }
    else
    {
        /* handle NULL pbuf (inner connection closed) */
        /* remote host sent FIN, remember this (SSL state is destroyed when both sides are closed only!) */
        if ((tlsSocketPtr->flags & (TLS_FLAGS_HANDSHAKE_DONE | TLS_FLAGS_UPPER_CALLED))
            == (TLS_FLAGS_HANDSHAKE_DONE | TLS_FLAGS_UPPER_CALLED))
        {
            if (tlsSocketPtr->rx != NULL)
            {
                tlsSocketPtr->flags |= TLS_FLAGS_RX_CLOSE_QUEUED;
                /* this is a normal close (FIN) but we have unprocessed data, so delay the FIN */
                (void)TcpIp_TlsHandleRxAppData(tpcb, sockeRuntimePtr);
                return (err_t)ERR_OK;
            }

            tlsSocketPtr->flags |= TLS_FLAGS_RX_CLOSED;
            /* shall notify upper fin receiver */
        }
        else
        {
            /* pending event notify */
            TcpIp_SocketFlagSet(sockeRuntimePtr, TCPIP_SOCKET_FLAG_TCP_PENDING_EVENT);
            /* before connection setup is done: call 'err' */
            SchM_Enter_TcpIp_ExclusiveArea_Tx();
            ret = tcp_close(tpcb);
            SchM_Exit_TcpIp_ExclusiveArea_Tx();
        }
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsErrCallBack(void* arg, err_t err)
{
    TcpIp_SocketRuntimeType* sockeRuntimePtr = (TcpIp_SocketRuntimeType*)arg;

    TcpIp_EventNotifyUpLayer(sockeRuntimePtr, (err != (err_t)ERR_CLSD) ? TCPIP_TCP_RESET : TCPIP_TCP_CLOSED);
    /* PRQA S 2144  */ /* VL_TcpIp_2144 */
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_TlsSocketInit(TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
    Std_ReturnType  ret             = E_NOT_OK;
    struct tcp_pcb* tpcb            = (struct tcp_pcb*)sockeRuntimePtr->PcbPtr;
    sockeRuntimePtr->tlsPtr->PcbPtr = (struct tcp_pcb*)sockeRuntimePtr->PcbPtr;
    sint32 mbRet                    = TcpIp_TlsBufSetup(&sockeRuntimePtr->tlsPtr->socketTlsContext);
    if (TLS_RETURN_OK != mbRet)
    {
        return E_NOT_OK;
    }

    /* cover reg callback function */
    /* shall reg recv function */
    tcp_recv(tpcb, TcpIp_TlsRecvCallBack); /* PRQA S 1334 */ /* VL_TcpIp_1334 */
    /* reg connect error callback function */
    tcp_err(tpcb, TcpIp_TlsErrCallBack);
    /* reg send call back function */
    tcp_sent(tpcb, NULL);
    ret = E_OK;

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsHandshakeDoneNotifyUpLayer(TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
    if (TLS_CLIENT == sockeRuntimePtr->tlsPtr->socketTlsContext.connectionConfigPtr->ConnectionType)
    {
        /* [SWS_TCPIP_00309] */
        /* <Up_TcpConnected> this function shall be called after the TLS handshake has been finished successfully */
        TcpIp_NotifyUpTcpConnected(sockeRuntimePtr);
    }
    else
    {
        /* [SWS_TCPIP_00310] */
        /* <Up_TcpAccepted> shall be called after the TLS handshake has been finished successfully */
        Std_ReturnType ret = TcpIp_NotifyUpTcpAccepted(sockeRuntimePtr->listenSocketId, sockeRuntimePtr);

        if ((Std_ReturnType)E_OK != ret)
        {
            /* if accept is not ok ,not continue notify upper layer event */
            tcp_err((struct tcp_pcb*)sockeRuntimePtr->PcbPtr, NULL_PTR);
            /* next shall close tcp pcb */
            (void)tcp_close((struct tcp_pcb*)sockeRuntimePtr->PcbPtr);
        }
    }

    /* [SWS_TCPIP_00345] */
    /* For static TLS connection assignment the call to <Up_TcpIpEvent> and the event type TCPIP_TLS_HANDSHAKE_SUCCEEDED
    shall take place after the call to <Up_TcpAccepted>/<Up_TcpConnected>. */
    TcpIp_EventNotifyUpLayer(sockeRuntimePtr, TCPIP_TLS_HANDSHAKE_SUCCEEDED);
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL sint32 TcpIp_TlsHandleRxAppData(struct tcp_pcb* tpcb, TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
    TCPIP_UNUSED_ARG(tpcb);
    if (TLS_MINOR_VERSION_4 == sockeRuntimePtr->tlsPtr->socketTlsContext.minorVersion)
    {
        return TcpIp_Tls13DecryptNotifyRecord(sockeRuntimePtr);
    }
    else
    {
        return TcpIp_Tls12DecryptNotifyRecord(sockeRuntimePtr);
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL err_t TcpIp_TlsRecvProcess(TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
    TcpIp_TlsSocketDataType* tlsSocketPtr = sockeRuntimePtr->tlsPtr;
    err_t                    ret          = (err_t)ERR_VAL;
    sint32                   tlsRet       = TLS_RETURN_OK;
    struct tcp_pcb*          tpcb         = sockeRuntimePtr->PcbPtr;

    if (tlsSocketPtr->flags & TLS_FLAGS_HANDSHAKE_DONE)
    {
        /* handle application data (handshake done) */
        tlsRet = TcpIp_TlsHandleRxAppData(tpcb, sockeRuntimePtr);

        (void)TcpIp_TlsRecved(sockeRuntimePtr, tlsSocketPtr->bioBytesRead);

        if (TLS_ERR_SSL_WANT_READ == tlsRet)
        {
            ret = (err_t)ERR_OK;
        }
        else if (tlsRet != TLS_RETURN_OK)
        {
            /* shall pending notify upper layer */
            TcpIp_SocketFlagSet(sockeRuntimePtr, (uint8)TCPIP_SOCKET_FLAG_TCP_PENDING_EVENT);
            /* handshake failed, connection has to be closed */
            if (tcp_close(tpcb) != ERR_OK)
            {
                tcp_abort(tpcb);
            }
        }
        else
        {
            /* No action required */
        }
    }
    else
    {
        /* handle connection setup (handshake not done) */
        tlsRet = TcpIp_TlsHandshakeStart(tlsSocketPtr);

        if (tlsSocketPtr->bioBytesRead)
        {
            /* acknowledge all bytes read */
            SchM_Enter_TcpIp_ExclusiveArea_Tx();
            tcp_recved(tpcb, tlsSocketPtr->bioBytesRead);
            SchM_Exit_TcpIp_ExclusiveArea_Tx();
            tlsSocketPtr->bioBytesRead = 0u;
        }

        switch (tlsRet)
        {
        case TLS_ERR_SSL_WANT_READ:
        case TLS_ERR_SSL_WANT_WRITE:
            /* handshake not done, wait for more recv calls */
            ret = (err_t)ERR_OK;
            break;

        case TLS_RETURN_OK:
            tlsSocketPtr->flags |= TLS_FLAGS_HANDSHAKE_DONE;
            /* issue "connect" callback" to upper connection (this can only happen for active open) */
            TcpIp_TlsHandshakeDoneNotifyUpLayer(sockeRuntimePtr);

            if (NULL_PTR == tlsSocketPtr->rx)
            {
                ret = (err_t)ERR_OK;
            }
            break;

        default:
            /* shall pending notify upper layer */
            TcpIp_SocketFlagSet(sockeRuntimePtr, (uint8)TCPIP_SOCKET_FLAG_TCP_PENDING_EVENT);
            /* handshake failed, connection has to be closed */
            if (tcp_close(tpcb) != ERR_OK)
            {
                tcp_abort(tpcb);
            }

            ret = (err_t)ERR_OK;
            break;
        }
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL err_t TcpIp_TlsConnected(void* arg, struct tcp_pcb* tpcb, err_t err)
{
    err_t                    ret             = (err_t)ERR_OK;
    TcpIp_SocketRuntimeType* sockeRuntimePtr = (TcpIp_SocketRuntimeType*)arg; /* PRQA S 0316 # void* cast intentional */

    TCPIP_UNUSED_ARG(tpcb);
    TCPIP_UNUSED_ARG(err);

    sockeRuntimePtr->tlsPtr->socketTlsContext.minorVersion = TLS_MINOR_VERSION_1;

    ret = TcpIp_TlsRecvProcess(sockeRuntimePtr);
    /* input parameter err not more condition, so not care other result */

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/***********************************************************************************************************************
 *  GLOBAL FUNCTIONS
 **********************************************************************************************************************/
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_TlsInit(const TcpIp_TlsConfigType* tlsCfgPtr)
{
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
    for (uint32 index = 0u; index < TLS_CONNGROUP_ARRY_SIZE; index++)
    {
        TcpIp_TlsConnectionGroupState[index] = 0u;
    }
#endif
    TcpIp_TlsSocketIdleListPtr = &TcpIp_TlsSocketDataTable[0u];

    for (uint32 index = 0u; index < (TCPIP_TLS_CONNECTION_NUMBER - 1u); index++)
    {
        TcpIp_TlsSocketDataTable[index].next = &TcpIp_TlsSocketDataTable[index + 1u];
    }

    TcpIp_TlsSocketDataTable[TCPIP_TLS_CONNECTION_NUMBER - 1u].next = NULL_PTR;
    TcpIp_TlsCfgPtr                                                 = tlsCfgPtr;

#if (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON)
    TcpIp_TlsHashInsert(tlsCfgPtr->ConnectionPtr);
#endif
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_TlsSocketDeInit(TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
    TcpIp_TlsSocketDataType* tlsSocketPtr = sockeRuntimePtr->tlsPtr;
    /* tls connnect group shall set not used */
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
    uintx tlsConnGrpCfgId = tlsSocketPtr->socketTlsContext.connectionConfigPtr->ConnectionGroupId;
    TLS_CONNGROUP_SET_UNUSED(tlsConnGrpCfgId);
#endif
    /* tls connect idle list shall change */
    tlsSocketPtr->next         = TcpIp_TlsSocketIdleListPtr;
    TcpIp_TlsSocketIdleListPtr = tlsSocketPtr;

    TcpIp_TlsFreeContex(tlsSocketPtr);

    sockeRuntimePtr->tlsPtr         = NULL_PTR;
    sockeRuntimePtr->listenSocketId = TCPIP_SOCKET_NUM;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsFreeContex(TcpIp_TlsSocketDataType* tlsSocketPtr)
{
    tlsContext* context = &tlsSocketPtr->socketTlsContext;

    TcpIp_TlsConnectionBusyStatus[context->connectionConfigPtr->ConnectionId] = FALSE;
    TcpIp_TlsHandshakeBusyStatus[context->handshakeId]                        = FALSE;
    TcpIp_TlsCiphersuiteBusyStatus[context->ciphersuiteId]                    = FALSE;

    pbuf_free(context->inPBuf);
    pbuf_free(context->outPBuf);

    IStdLib_MemSet(context, 0u, sizeof(tlsContext));
    tlsSocketPtr->PcbPtr           = NULL;
    tlsSocketPtr->rx               = NULL;
    tlsSocketPtr->flags            = 0u;
    tlsSocketPtr->rxPassedUnrecved = 0u;
    tlsSocketPtr->bioBytesRead     = 0u;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
err_t TcpIp_TlsHandleTxAppData(const TcpIp_SocketRuntimeType* sockeRuntimePtr, const uint8* dataptr, uint16 len)
{
    Std_ReturnType           Std_Return       = E_OK;
    uint16                   remainingDataLen = len, curPlainTextLen = 0u;
    const uint8*             curPlainTextPtr = dataptr;
    TcpIp_TlsSocketDataType* tlsSocketPtr    = sockeRuntimePtr->tlsPtr;
    tlsContext*              context         = &tlsSocketPtr->socketTlsContext;
    uint16 maxPlainTextSize = tlsSocketPtr->socketTlsContext.recordSizeLimit - 1u; /* reserve 1B for padding */

    if ((tlsSocketPtr->flags & TLS_FLAGS_HANDSHAKE_DONE) == 0u)
    {
        return (err_t)ERR_VAL;
    }
    context->outRecordContentType = TLS_MSG_TYPE_APPLICATION_DATA;

    while (remainingDataLen)
    {
        curPlainTextLen = (remainingDataLen < maxPlainTextSize) ? remainingDataLen : maxPlainTextSize;
#if (STD_ON == TLS_ENCRYPT_THEN_MAC)
        context->encryptThenMac = 0u; /* for debug */
#endif
        if (TLS_MINOR_VERSION_4 == context->minorVersion)
        {
            /* TLS 1.3 */
            Std_Return = TcpIp_Tls13EncryptWriteRecord(tlsSocketPtr, curPlainTextPtr, curPlainTextLen);
            if (E_OK != Std_Return)
            {
                return (err_t)ERR_VAL;
            }
        }
        else
        {
            /* TLS 1.2 */
            if ((FALSE == context->ciphersuiteDefinitionPtr->UseAEADCipher) /* PRQA S 2120 */ /* VL_TcpIp_2120 */
#if (STD_ON == TLS_ENCRYPT_THEN_MAC)
                && (FALSE == context->encryptThenMac)
#endif
            )
            {
                Std_Return = TcpIp_Tls12EncryptWriteRecord(tlsSocketPtr, curPlainTextPtr, curPlainTextLen);
                if (E_OK != Std_Return)
                {
                    return (err_t)ERR_VAL;
                }
            }
            else
            {
                /* todo: AEAD, encrypt then mac */
            }
        }

        remainingDataLen -= curPlainTextLen;
        curPlainTextPtr += (sint32)curPlainTextLen;
    }

    return (err_t)ERR_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL void TcpIp_TlsSockeRuntimeInsert(TcpIp_SocketRuntimeType* sockeRuntimePtr)
{
#if (STD_ON != TCPIP_PARTITION_USED)
    ApplicationType partitionIndex = 0u;
#else
    uint8                 ctrlIndex      = sockeRuntimePtr->CtrlIndex;
    const TcpIp_CtrlType* ctrlCfgPtr     = &TCPIP_CTRL_CONFIG(ctrlIndex);
    ApplicationType       partitionIndex = ctrlCfgPtr->PartitionIndex;
#endif
    TcpIp_SocketRuntimeType** sockeRuntimeHead = &TcpIp_TlsSockeRuntimeHead[partitionIndex];

    /* insert into tail of list; process from head (reader/writer queue) */
    if (NULL == *sockeRuntimeHead)
    {
        *sockeRuntimeHead = sockeRuntimePtr;
    }
    else
    {
        TcpIp_SocketRuntimeType* lastNode = *sockeRuntimeHead;
        while (lastNode->NextSocketRuntimePtr)
        {
            lastNode = lastNode->NextSocketRuntimePtr;
        }

        lastNode->NextSocketRuntimePtr = sockeRuntimePtr;
    }
    sockeRuntimePtr->NextSocketRuntimePtr = NULL;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_TlsSockeRuntimeProcess(ApplicationType partitionIndex)
{
    TcpIp_SocketRuntimeType** sockeRuntimeHead = &TcpIp_TlsSockeRuntimeHead[partitionIndex];
    while (*sockeRuntimeHead)
    {
        TcpIp_SocketRuntimeType* CurrentTlsSockeRuntimePtr = *sockeRuntimeHead;
        while ((CurrentTlsSockeRuntimePtr->tlsPtr) && (CurrentTlsSockeRuntimePtr->tlsPtr->rx))
        {
            /* maybe we receive multi pbuf but only be notified once */
            (void)TcpIp_TlsRecvProcess(CurrentTlsSockeRuntimePtr);
        }
        TcpIp_EnterExclusiveArea();
        *sockeRuntimeHead                               = CurrentTlsSockeRuntimePtr->NextSocketRuntimePtr;
        CurrentTlsSockeRuntimePtr->NextSocketRuntimePtr = NULL;
        TcpIp_ExitExclusiveArea();
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_TlsRecved(const TcpIp_SocketRuntimeType* sockeRuntimePtr, uint16 len)
{
    Std_ReturnType           ret          = E_NOT_OK;
    TcpIp_TlsSocketDataType* tlsSocketPtr = sockeRuntimePtr->tlsPtr;
    TCPIP_UNUSED_ARG(len);

    if ((tlsSocketPtr->flags & TLS_FLAGS_HANDSHAKE_DONE) != 0u)
    {
        uint16 lwReceLen = len;

        if ((uint32)lwReceLen > tlsSocketPtr->rxPassedUnrecved)
        {
            lwReceLen = (uint16)tlsSocketPtr->rxPassedUnrecved;
        }

        tlsSocketPtr->rxPassedUnrecved -= (uint32)lwReceLen;
        SchM_Enter_TcpIp_ExclusiveArea_Tx();
        tcp_recved((struct tcp_pcb*)(sockeRuntimePtr->PcbPtr), lwReceLen);
        SchM_Exit_TcpIp_ExclusiveArea_Tx();
        ret = E_OK;
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
err_t TcpIp_TlsConnet(struct tcp_pcb* tpcb, ip_addr_t* ipaddr, uint16 port)
{
    SchM_Enter_TcpIp_ExclusiveArea_Tx();
    err_t lw_ret = (err_t)tcp_connect(tpcb, ipaddr, port, TcpIp_TlsConnected);
    SchM_Exit_TcpIp_ExclusiveArea_Tx();
    return lw_ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_TlsBaseDynamicConnect(TcpIp_SocketRuntimeType* sockeRuntimePtr, uint16 tlsConnetId)
{
    Std_ReturnType ret = E_NOT_OK;

    const TcpIp_TlsConnectionConfigType* tlsCnCfgPtr = &TcpIp_TlsCfgPtr->ConnectionPtr[tlsConnetId];
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
    uint8 tlsConnGrpCfgId = tlsCnCfgPtr->ConnectionGroupId;
#endif
    /* based on either static configuration  or done dynamically,so  dynamically is not set exist tls connection*/
    if ((NULL_PTR == sockeRuntimePtr->tlsPtr) && (NULL_PTR != TcpIp_TlsSocketIdleListPtr)
        && (FALSE == TcpIp_TlsConnectionBusyStatus[tlsCnCfgPtr->ConnectionId])
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
        && (!TLS_CONNGROUP_IS_USED(tlsConnGrpCfgId))
#endif
    )
    {
        /* init handle shall be add */
        sockeRuntimePtr->tlsPtr                                       = TcpIp_TlsSocketIdleListPtr;
        sockeRuntimePtr->tlsPtr->socketTlsContext.connectionConfigPtr = tlsCnCfgPtr;
        TcpIp_TlsConnectionBusyStatus[tlsCnCfgPtr->ConnectionId]      = TRUE;
        ret                                                           = TcpIp_TlsSocketInit(sockeRuntimePtr);

        if ((Std_ReturnType)E_OK == ret)
        {
            TcpIp_TlsSocketIdleListPtr = TcpIp_TlsSocketIdleListPtr->next;
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
            TLS_CONNGROUP_SET_USED(tlsConnGrpCfgId);
#endif
        }
        else
        {
            /* tls socket init error,shall release socket manage link tls data point ,
            this socket shall be change normal state is not tls */
            sockeRuntimePtr->tlsPtr = NULL_PTR;
        }
    }

    return ret;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_TlsBaseStaticConnect(
    TcpIp_SocketRuntimeType*         sockeRuntimePtr,
    const TcpIp_SockAddrType*        staticAddrPtr,
    TcpIp_TlsConnectionInitStateType connType)
{
    const TcpIp_TlsConnectionConfigType* tlsCnCfgPtr = NULL_PTR;
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
    uintx tlsConnGrpCfgId = 0u;
#endif

    if (NULL_PTR == TcpIp_TlsSocketIdleListPtr)
    {
        return;
    }

#if (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON)
    tlsCnCfgPtr = TcpIp_TlsHashLookup(staticAddrPtr->addr[0u], staticAddrPtr->port, connType);
    if (NULL == tlsCnCfgPtr)
    {
        return;
    }
    sockeRuntimePtr->tlsPtr = TcpIp_TlsSocketIdleListPtr;
#else
    /* find idle tls connect */
    for (uint32 index = 0u; index < TCPIP_TLS_CONNECTION_NUMBER; index++) /* PRQA S 0771 */ /* VL_TcpIp_0771 */
    {
        tlsCnCfgPtr = &TcpIp_TlsCfgPtr->ConnectionPtr[index];
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
        if (0xFFu != tlsCnCfgPtr->ConnectionGroupId)
        {
            tlsConnGrpCfgId = tlsCnCfgPtr->ConnectionGroupId;
        }
#endif

        if ((connType == tlsCnCfgPtr->ConnectionType) && (FALSE == TcpIp_TlsConnectionBusyStatus[index])
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
            && !TLS_CONNGROUP_IS_USED(tlsConnGrpCfgId)
#endif
            && (tlsCnCfgPtr->PortAssignment != 0u) && (tlsCnCfgPtr->PortAssignment == staticAddrPtr->port))
        {
            const TcpIp_LocalAddrType* localAddrTypePtr = tlsCnCfgPtr->IpAddressAssignment;
            if ((NULL_PTR == localAddrTypePtr) || (NULL_PTR == localAddrTypePtr->IpAddrCfgPtr))
            {
                sockeRuntimePtr->tlsPtr = TcpIp_TlsSocketIdleListPtr;
                break;
            }
            else
            {
                uint32 ipAddr = *localAddrTypePtr->IpAddrCfgPtr->StaticIpAddrPtr;
                if ((localAddrTypePtr->CtrlIndex == sockeRuntimePtr->CtrlIndex) &&
#if (TCPIP_SC1 == TCPIP_SCALABILITY_CLASS)
                    (ipAddr == staticAddrPtr->addr[0u])
#else
                    (ipAddr[0u] == staticAddrPtr->addr[0u]) && (ipAddr[1u] == staticAddrPtr->addr[1u])
                    && (ipAddr[2u] == staticAddrPtr->addr[2u]) && (ipAddr[3u] == staticAddrPtr->addr[3u])
#endif
                )
                {
                    sockeRuntimePtr->tlsPtr = TcpIp_TlsSocketIdleListPtr;
                    break;
                }
            }
        }
    }

    if (NULL == sockeRuntimePtr->tlsPtr)
    {
        return;
    }
#endif /* (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON) */

    sockeRuntimePtr->tlsPtr->socketTlsContext.connectionConfigPtr = tlsCnCfgPtr;
    TcpIp_TlsConnectionBusyStatus[tlsCnCfgPtr->ConnectionId]      = TRUE;
    Std_ReturnType ret                                            = TcpIp_TlsSocketInit(sockeRuntimePtr);

    if ((Std_ReturnType)E_OK == ret)
    {
        TcpIp_TlsSocketIdleListPtr = TcpIp_TlsSocketIdleListPtr->next;
#if (TCPIP_TCP_TLS_CONNECTION_GROUP_NUM > 0u)
        TLS_CONNGROUP_SET_USED(tlsConnGrpCfgId);
#endif
    }
    else
    {
        /* tls socket init error,shall release socket manage link tls data point ,
        this socket shall be change normal state is not tls */
        sockeRuntimePtr->tlsPtr = NULL_PTR;
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_TlsCsmRandomGenerate(uint8* resultPtr, uint32* resultLengthPtr)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint32         randJobId  = TcpIp_TlsCfgPtr->CsmRandomGenerateJobId;
    uint32         randKeyId  = TcpIp_TlsCfgPtr->CsmRandomGenerateKeyId;
    (void)Csm_KeySetValid(randKeyId);
    Std_Return = Csm_RandomGenerate(randJobId, CRYPTO_OPERATIONMODE_SINGLECALL, resultPtr, resultLengthPtr);
    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#endif /* (STD_ON == TCPIP_TCP_TLS_ENABLED) */
