/*******************************************************************************
**                                                                            **
** Copyright (C) iSOFT   (2022)                                               **
**                                                                            **
** All rights reserved.                                                       **
**                                                                            **
** This document contains proprietary information belonging to iSOFT.         **
** Passing on and copying of this document, and communication                 **
** of its contents is not permitted without prior written authorization.      **
**                                                                            **
********************************************************************************
**                                                                            **
**  FILENAME    : TcpIp_Ike.h                                                 **
**                                                                            **
**  Created on  :                                                             **
**  Author      : xiankun.zhou                                                **
**  Vendor      : i-soft                                                      **
**  DESCRIPTION : function declaration of tcp_tls                             **
**                                                                            **
**  SPECIFICATION(S) :   AUTOSAR classic Platform R19-11                      **
**                                                                            **
*******************************************************************************/
/*******************************************************************************
**                      REVISION   HISTORY                                    **
*******************************************************************************/
/* <VERSION>    <DATE>       <AUTHOR>        <REVISION LOG>
 *  V2.2.0    [20250729]  [xiankun.zhou]  Create file.
 ******************************************************************************/

/*******************************************************************************
**                      Include Section                                       **
*******************************************************************************/
#ifndef TCPIP_IKE_H_
#define TCPIP_IKE_H_
#include "TcpIp_Ike_Types.h"
#if (STD_ON == TCPIP_IPSEC_ENABLED)
#define IKE_USE_CSM_API STD_OFF

/*************************Function Declaration***********************************/
#include "Std_Types.h"
/********************************************************************************************/

/*************************************** Extensions *************************************************/
#define IKE_IN_BUFFER_LEN  2048u
#define IKE_OUT_BUFFER_LEN 2048u

#define IKE_MAJOR_VERSION 2u
#define IKE_MINOR_VERSION 0u
#define IKE_VERSION_2     0x20u

/********************** Next Payload Type ***********************/
#define IKE_NEXT_PAYLOAD_TYPE_NONE    0u
#define IKE_NEXT_PAYLOAD_TYPE_SA      33u
#define IKE_NEXT_PAYLOAD_TYPE_KE      34u
#define IKE_NEXT_PAYLOAD_TYPE_IDI     35u
#define IKE_NEXT_PAYLOAD_TYPE_IDR     36u
#define IKE_NEXT_PAYLOAD_TYPE_CERT    37u
#define IKE_NEXT_PAYLOAD_TYPE_CERTREQ 38u
#define IKE_NEXT_PAYLOAD_TYPE_AUTH    39u
#define IKE_NEXT_PAYLOAD_TYPE_NONCE   40u
#define IKE_NEXT_PAYLOAD_TYPE_NOTIFY  41u
#define IKE_NEXT_PAYLOAD_TYPE_TSI     44u
#define IKE_NEXT_PAYLOAD_TYPE_TSR     45u
#define IKE_NEXT_PAYLOAD_TYPE_SK      46u

/********************** exchange type ***********************/
#define IKE_EXCHANGE_TYPE_SA_INIT         34u
#define IKE_EXCHANGE_TYPE_AUTH            35u
#define IKE_EXCHANGE_TYPE_CREATE_CHILD_SA 36u
#define IKE_EXCHANGE_TYPE_INFORMATIONAL   37u

/********************** notify type ***********************/
#define IKE_NOTIFY_TYPE_USE_TRANSPORT_MODE 16391u

#define IKE_INITIATOR_BIT ((uint8)3u)
#define IKE_VERSION_BIT   ((uint8)4u)
#define IKE_RESPONDER_BIT ((uint8)5u)
#define IKE_TV_FORMAT_BIT ((uint8)7u)

#define IPSEC_PROTOCOL_ID_IKE 1u
#define IPSEC_PROTOCOL_ID_AH  2u
#define IPSEC_PROTOCOL_ID_ESP 3u

#define TRANSFORM_LAST_SUBSTRUC      0u
#define TRANSFORM_NONE_LAST_SUBSTRUC 3u

#define TRANSFORM_ALGO_ENCR  1u
#define TRANSFORM_ALGO_PRF   2u
#define TRANSFORM_ALGO_INTEG 3u
#define TRANSFORM_ALGO_DH    4u
#define TRANSFORM_ALGO_ESN   5u

#define TRANSFORM_ATTRIBUTE_VALUE_KEY_LEN 14u

#define IKE_PRF_OUTPUT_MAX_LEN 32u
#define IKE_PSK_KEY_MAX_LEN    64u

#define IKE_ID_IPV4_ADDR   1u
#define IKE_ID_FQDN        2u
#define IKE_ID_RFC822_ADDR 3u
#define IKE_ID_IPV6_ADDR   5u

#define IKE_AUTH_METHOD_RSA   1u
#define IKE_AUTH_METHOD_PSK   2u
#define IKE_AUTH_METHOD_DSS   3u
#define IKE_AUTH_METHOD_ECDSA 9u
#define IKE_AUTH_METHOD_EAP   13u

#define IKE_TS_IPV4_ADDR_RANGE 7u
#define IKE_TS_IPV6_ADDR_RANGE 8u

#define IKE_HMAC_SHA1_KEY_LEN     20u
#define IKE_HMAC_SHA2_256_KEY_LEN 32u
#define IKE_HMAC_SHA2_384_KEY_LEN 48u
#define IKE_HMAC_SHA2_512_KEY_LEN 64u

#define IKE_HMAC_SHA1_96_OUTPUT_LEN      12u
#define IKE_HMAC_SHA2_256_128_OUTPUT_LEN 16u
#define IKE_HMAC_SHA1_384_192_OUTPUT_LEN 24u
#define IKE_HMAC_SHA1_512_256_OUTPUT_LEN 32u

#define IKE_DH_CURVE25519_KEY_LEN 32u

#define IKE_LABEL_KEY_PAD "Key Pad for IKEv2"

/*********************************** ERROR CODE *****************************************/
typedef uint8 u8;
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_IkeInit();
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_IkeInitHandle(uint16 partitionIndex);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType
    TcpIp_HMAC_hash(uint8* key, uint32 keyLen, uint8* input, uint32 inputLen, uint8* output, uint32* outputLen);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType Ipsec_IkeSaKeysGenerate(IkeConnContext* context);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType Ipsec_ChildSaKeysGenerate(IkeConnContext* context, TcpIp_IpSecSAType* childSA);
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"
#endif /* TCPIP_IPSEC_ENABLED */
#endif /* TCPIP_IKE_H_ */
