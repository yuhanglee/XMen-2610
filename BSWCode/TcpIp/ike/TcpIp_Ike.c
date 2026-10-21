/***********************************************************************************************************************
**                                                                                                                    **
** Copyright (C) iSOFT   (2022)                                                                                       **
**                                                                                                                    **
** All rights reserved.                                                                                               **
**                                                                                                                    **
** This document contains proprietary information belonging to iSOFT                                                  **
** Passing on and copying of this document, and communication                                                         **
** of its contents is not permitted without prior written authorization.                                              **
**                                                                                                                    **
************************************************************************************************************************
**                                                                                                                    **
**  FILENAME    : TcpIp_Ipsec.c                                                                                     **
**                                                                                                                    **
**  Created on  : 15/07/25                                                                                            **
**  Author      : xiankun.zhou                                                                                        **
**  Vendor      :                                                                                                     **
**  DESCRIPTION : internal type definition for TcpIp                                                                  **
**                                                                                                                    **
**  SPECIFICATION(S) :   AUTOSAR classic Platform R24-11                                                              **
**                                                                                                                    **
***********************************************************************************************************************/

/***********************************************************************************************************************
**                                          REVISION   HISTORY                                                        **
***********************************************************************************************************************/
/* <VERSION>    <DATE>       <AUTHOR>        <REVISION LOG>
 *  V2.2.0    [20250715]  [xiankun.zhou]  Create file
 **********************************************************************************************************************/
/* PRQA S 0553 EOF */ /* VL_QAC_UnUsedFiles */
/* PRQA S 6520 EOF */ /* VL_MTR_TcpIp_STVAR */

#include "Std_Types.h"
#include "TcpIp_Cfg.h"
#include "TcpIp_Types.h"
#include "TcpIp_Internal.h"
#include "SchM_TcpIp.h"
#include "TcpIp_PBcfg.h"
#include "Csm.h"
#include "TcpIp_Ike_Types.h"
#include "TcpIp_CfgTypes.h"
#include "TcpIp_Ike.h"
#include "IStdLib.h"
#include "Bfx.h"

#if (STD_ON == TCPIP_IPSEC_ENABLED)

#define TCPIP_START_SEC_CONFIG_DATA_UNSPECIFIED
#include "TcpIp_MemMap.h"
extern const IKE_ConfigType IKE_Config;
#define TCPIP_STOP_SEC_CONFIG_DATA_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CONFIG_DATA_UNSPECIFIED
#include "TcpIp_MemMap.h"
extern const TcpIp_IpSecConfigSetType TcpIp_IpSecPbCfg;
#define TCPIP_STOP_SEC_CONFIG_DATA_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
IkeConnContext IkeConnContextTable[IKE_CONNECTION_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"
TcpIp_IpSecSAType TcpIp_IpSecSadSpdList[TCPIP_MAX_SA_NUMBER];
#define TCPIP_STOP_SEC_VAR_CLEARED_UNSPECIFIED
#include "TcpIp_MemMap.h"

#define TCPIP_IKE_MS_TO_TICK(ms) \
    ((((uint32)(ms)) + ((uint32)TCPIP_MAINFUNCTION_PERIOD - 1u)) / (uint32)TCPIP_MAINFUNCTION_PERIOD)

TCPIP_LOCAL_INLINE boolean TcpIp_IkeUpdateRetransmitTickAndCheckTimeout(IkeConnContext* context)
{
    if (context->RetransmitRemainTick > 0u)
    {
        context->RetransmitRemainTick--;
    }

    return (boolean)(context->RetransmitRemainTick == 0u);
}

TCPIP_LOCAL_INLINE void TcpIp_IkeReloadRetransmitTick(IkeConnContext* context)
{
    context->RetransmitRemainTick = TCPIP_IKE_MS_TO_TICK(context->RetransmitTimeoutMs);
}

/**
 * @brief         Encodes a 32-bit parameter into a buffer in big-endian format.
 * @param[in,out] buffer: Pointer to the buffer where the parameter will be encoded.
 * @param[in]     paramenter: The 32-bit parameter to encode.
 * @return        None
 * @reentrant     FALSE
 * @synchronous   TRUE
 * @trace       CPD-74661
 */
TCPIP_LOCAL_INLINE void TCPIP_CHG_PARA_ENCODE_32(uint8* buffer, uint32 paramenter)
{
    (buffer)[0u] = (uint8)((paramenter) >> 24u);
    (buffer)[1u] = (uint8)((paramenter) >> 16u);
    (buffer)[2u] = (uint8)((paramenter) >> 8u);
    (buffer)[3u] = (uint8)(paramenter);
}

TCPIP_LOCAL_INLINE void TcpIp_IkeCopyU32(uint32* dst, const uint8* src)
{
    uint8* d = (uint8*)dst;

    d[0u] = src[0u];
    d[1u] = src[1u];
    d[2u] = src[2u];
    d[3u] = src[3u];
}

/**
 * @brief		bind a child SA to current IKE context.
 * @param[in]	context   : IKE context pointer.
                SAId      : child SA index.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
TCPIP_LOCAL_INLINE void TcpIp_IkeBindChildSA(IkeConnContext* context, uint8 SAId)
{
    Bfx_SetBit_u16u8(&context->SABitMap, SAId);
}

/**
 * @brief		unbind a child SA to current IKE context.
 * @param[in]	context   : IKE context pointer.
                SAId      : child SA index.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
TCPIP_LOCAL_INLINE void TcpIp_IkeUnbindChildSA(IkeConnContext* context, uint8 SAId)
{
    Bfx_ClrBit_u16u8(&context->SABitMap, SAId);
}

/**
 * @brief		Rollback a child SA allocation: clear InboundActive/OutboundActive flags
 *              and unbind the SA from the IKE context. Should be called on negotiation
 *              failure after a child SA has already been allocated and bound.
 * @param[in]	context   : IKE context pointer.
 *              childSA   : pointer to the child SA to rollback.
 * @return		None.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
TCPIP_LOCAL_INLINE void TcpIp_IkeRollbackChildSA(IkeConnContext* context, TcpIp_IpSecSAType* childSA)
{
    uint32 SAId = (uint32)(childSA - &TcpIp_IpSecSadSpdList[0]);
    if (SAId < TCPIP_MAX_SA_NUMBER)
    {
        childSA->InboundActive  = FALSE;
        childSA->OutboundActive = FALSE;
        TcpIp_IkeUnbindChildSA(context, (uint8)SAId);
    }
}

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		find an idle Outbound child SA for current IKE context.
 * @param[in]	context   : IKE context pointer.
 * @return		TcpIp_IpSecSAType pointer.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
TCPIP_LOCAL TcpIp_IpSecSAType* TcpIp_IkeFindOutboundChildSA(IkeConnContext* context)
{
    for (uint32 i = 0; i < TCPIP_MAX_SA_NUMBER; i++)
    {
        if (FALSE == TcpIp_IpSecSadSpdList[i].OutboundActive)
        {
            TcpIp_IkeBindChildSA(context, i);
            TcpIp_IpSecSadSpdList[i].OutboundActive = TRUE;
            return &TcpIp_IpSecSadSpdList[i];
        }
    }

    return NULL;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		find an idle Inbound child SA for current IKE context.
 * @param[in]	context   : IKE context pointer.
 * @return		TcpIp_IpSecSAType pointer.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
TCPIP_LOCAL TcpIp_IpSecSAType* TcpIp_IkeFindInboundChildSA(IkeConnContext* context)
{
    for (uint32 i = 0; i < TCPIP_MAX_SA_NUMBER; i++)
    {
        if ((context->SABitMap & (1u << i)) && (FALSE == TcpIp_IpSecSadSpdList[i].InboundActive))
        {
            TcpIp_IpSecSadSpdList[i].InboundActive = TRUE;
            return &TcpIp_IpSecSadSpdList[i];
        }
    }

    return NULL;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		IKE buffer alloc and set up.
 * @param[in]	context   : IKE context pointer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_IkeBufSetup(IkeConnContext* context)
{
    context->inPBuf = pbuf_alloc(PBUF_RAW, IKE_IN_BUFFER_LEN, PBUF_RAM);

    if (NULL_PTR == context->inPBuf)
    {
        return E_NOT_OK;
    }

    context->outPBuf = pbuf_alloc(PBUF_RAW, IKE_OUT_BUFFER_LEN, PBUF_RAM);
    if (NULL_PTR == context->outPBuf)
    {
        pbuf_free(context->inPBuf);
        return E_NOT_OK;
    }

    context->inBufPtr  = context->inPBuf->payload;
    context->outBufPtr = context->outPBuf->payload;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_IkeInit()
{
    IStdLib_MemSet(IkeConnContextTable, 0, sizeof(IkeConnContextTable));
    IStdLib_MemSet(TcpIp_IpSecSadSpdList, 0, sizeof(TcpIp_IpSecSadSpdList));

    for (uint32 i = 0; i < IKE_CONNECTION_NUMBER; i++)
    {
        IkeConnContext* context = &IkeConnContextTable[i];

        context->ConnStatus            = IKE_CONN_CLOSED;
        context->SocketId              = TCPIP_SOCKETID_INVALID;
        context->RetransmitTimeoutMs   = IKE_Config.Connections->RetransmitTimeout;
        context->EncrTransformPbCfgId  = 0xFFu;
        context->PrfTransformPbCfgId   = 0xFFu;
        context->IntegTransformPbCfgId = 0xFFu;
        context->DhTransformPbCfgId    = 0xFFu;

        TcpIp_IkeBufSetup(context);
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeParseSa1Proposal(IkeConnContext* context, const uint8** parsePtrP)
{
    const uint8* parsePtr    = *parsePtrP;
    uint8        nextPayload = 0;

    uint8 transformNum = parsePtr[7];
    if (4 != transformNum)
    {
        return E_NOT_OK;
    }
    parsePtr += 8;

    do
    {
        nextPayload = parsePtr[0];

        uint16 payloadLen    = (uint16)((parsePtr[2] << 8) | parsePtr[3]);
        uint8  transformType = parsePtr[4];
        uint16 transformId   = (uint16)((parsePtr[6] << 8) | parsePtr[7]);
        uint16 keyLen        = 0;

        if ((payloadLen > 8) && (TRANSFORM_ALGO_ENCR == transformType))
        {
            /* transform attribute */
            keyLen = (uint16)((parsePtr[10] << 8) | parsePtr[11]);
        }

        parsePtr += payloadLen;

        switch (transformType)
        {
        case TRANSFORM_ALGO_ENCR:
            for (uint32 i = 0; i < IKE_ENCR_TRANSFORM_NUMBER; i++)
            {
                if ((IKE_Config.Transforms->EncrTransform[i].TransformId == transformId)
                    && (IKE_Config.Transforms->EncrTransform[i].KeyLength == keyLen))
                {
                    context->EncrTransformPbCfgId = i;
                    context->EncrKeyLen           = keyLen >> 3;
                    break;
                }
            }
            break;

        case TRANSFORM_ALGO_PRF:
            for (uint32 i = 0; i < IKE_PRF_TRANSFORM_NUMBER; i++)
            {
                if (IKE_Config.Transforms->PrfTransform[i].TransformId == transformId)
                {
                    context->PrfTransformPbCfgId = i;
                    switch (transformId)
                    {
                    case IKE_TRANSFORM_PRF_HMAC_SHA1:
                        context->PrfKeyLen = IKE_HMAC_SHA1_KEY_LEN;
                        break;
                    case IKE_TRANSFORM_PRF_HMAC_SHA2_256:
                        context->PrfKeyLen = IKE_HMAC_SHA2_256_KEY_LEN;
                        break;
                    case IKE_TRANSFORM_PRF_HMAC_SHA2_384:
                        context->PrfKeyLen = IKE_HMAC_SHA2_384_KEY_LEN;
                        break;
                    case IKE_TRANSFORM_PRF_HMAC_SHA2_512:
                        context->PrfKeyLen = IKE_HMAC_SHA2_512_KEY_LEN;
                        break;
                    default:
                        break;
                    }

                    break;
                }
            }
            break;

        case TRANSFORM_ALGO_INTEG:
            for (uint32 i = 0; i < IKE_INTEG_TRANSFORM_NUMBER; i++)
            {
                if (IKE_Config.Transforms->IntegTransform[i].TransformId == transformId)
                {
                    context->IntegTransformPbCfgId = i;
                    switch (transformId)
                    {
                    case IKE_TRANSFORM_AUTH_HMAC_SHA1_96:
                        context->IntegKeyLen    = IKE_HMAC_SHA1_KEY_LEN;
                        context->IntegOutputLen = IKE_HMAC_SHA1_96_OUTPUT_LEN;
                        break;
                    case IKE_TRANSFORM_AUTH_HMAC_SHA2_256_128:
                        context->IntegKeyLen    = IKE_HMAC_SHA2_256_KEY_LEN;
                        context->IntegOutputLen = IKE_HMAC_SHA2_256_128_OUTPUT_LEN;
                        break;
                    case IKE_TRANSFORM_AUTH_HMAC_SHA2_384_192:
                        context->IntegKeyLen    = IKE_HMAC_SHA2_384_KEY_LEN;
                        context->IntegOutputLen = IKE_HMAC_SHA1_384_192_OUTPUT_LEN;
                        break;
                    case IKE_TRANSFORM_AUTH_HMAC_SHA2_512_256:
                        context->IntegKeyLen    = IKE_HMAC_SHA2_512_KEY_LEN;
                        context->IntegOutputLen = IKE_HMAC_SHA1_512_256_OUTPUT_LEN;
                        break;
                    default:
                        break;
                    }

                    break;
                }
            }
            break;

        case TRANSFORM_ALGO_DH:
            for (uint32 i = 0; i < IKE_DH_TRANSFORM_NUMBER; i++)
            {
                if (IKE_Config.Transforms->DhTransform[i].TransformId == transformId)
                {
                    context->DhTransformPbCfgId = i;
                    switch (transformId)
                    {
                    case IKE_TRANSFORM_DH_CURVE25519:
                        context->DHKeyLen = IKE_DH_CURVE25519_KEY_LEN;
                        break;
                    default:
                        break;
                    }

                    break;
                }
            }
            break;

        default:
            break;
        }
    } while (TRANSFORM_LAST_SUBSTRUC != nextPayload);

    *parsePtrP = parsePtr;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeParseSaInit(IkeConnContext* context, const uint8* parsePtr)
{
    Std_ReturnType             Std_Return                     = E_OK;
    uint8                      peerPubKey[IKE_DH_KEY_MAX_LEN] = {0};
    uint32                     dhPublicKeyLen                 = 0;
    const IKE_DhTransformType* dhTransformPtr                 = NULL;

    /* save ResponderSPI */
    IStdLib_MemCpy(context->ResponderSPI, parsePtr, IKE_IKE_SPI_LEN);
    parsePtr += IKE_IKE_SPI_LEN;

    uint8 nextPayload = parsePtr[0];
    parsePtr++;

    /* version check */
    if (IKE_VERSION_2 != parsePtr[0])
    {
        return E_NOT_OK;
    }
    parsePtr++;

    /* EXCHANGE_TYPE check */
    if (IKE_EXCHANGE_TYPE_SA_INIT != parsePtr[0])
    {
        return E_OK;
    }
    /* skip flags*/
    parsePtr += 2;

    uint32 messageId = TCPIP_CHANGEPARAMETER_DECODE_U32(parsePtr);
    if (messageId < context->PeerMessageId)
    {
        return E_OK;
    }
    /* skip length*/
    parsePtr += 8;

    /* payload parse, now parsePtr point to payload */
    while (IKE_NEXT_PAYLOAD_TYPE_NONE != nextPayload)
    {
        uint8 curPayload = nextPayload;

        /* parse next payload */
        nextPayload = parsePtr[0];

        /* parse payload len */
        uint16 payloadLen = (uint16)((parsePtr[2] << 8) | parsePtr[3]);
        parsePtr += 4;

        switch (curPayload)
        {
        case IKE_NEXT_PAYLOAD_TYPE_SA:
            Std_Return = TcpIp_IkeParseSa1Proposal(context, &parsePtr);
            break;

        case IKE_NEXT_PAYLOAD_TYPE_KE:
        {
            dhTransformPtr = &IKE_Config.Transforms->DhTransform[context->DhTransformPbCfgId];
            uint16 DHGroup = (uint16)((parsePtr[0] << 8) | parsePtr[1]);
            if (dhTransformPtr->TransformId != DHGroup)
            {
                return E_NOT_OK;
            }
            dhPublicKeyLen = payloadLen - 8;
            IStdLib_MemCpy(peerPubKey, &parsePtr[4], dhPublicKeyLen);
            parsePtr += (payloadLen - 4);
            break;
        }

        case IKE_NEXT_PAYLOAD_TYPE_NONCE:
            context->ResponderNonceLen = payloadLen - 4;
            IStdLib_MemCpy(context->ResponderNonce, parsePtr, context->ResponderNonceLen);
            IStdLib_MemCpy(
                &context->InitiatorSignedOctets[context->RealMessage1Len],
                parsePtr,
                context->ResponderNonceLen);
            parsePtr += (payloadLen - 4);
            break;

        default:
            parsePtr += (payloadLen - 4);
            break;
        }
    }

    uint8  dhSharedKey[IKE_DH_KEY_MAX_LEN] = {0};
    uint32 dhSharedKeyLen                  = IKE_DH_KEY_MAX_LEN;
    uint32 dhKeyId                         = dhTransformPtr->KeyId;
    (void)Csm_KeySetValid(dhKeyId);
    Std_Return = Csm_KeyExchangeCalcSecret(dhKeyId, peerPubKey, dhPublicKeyLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(dhKeyId);
    Std_Return = Csm_KeyElementGet(dhKeyId, CRYPTO_KE_KEYEXCHANGE_SHAREDVALUE, dhSharedKey, &dhSharedKeyLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    IStdLib_MemCpy(context->DHKey, dhSharedKey, context->DHKeyLen);

    Std_Return = Ipsec_IkeSaKeysGenerate(context);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    context->RetransmitTries      = 0;
    context->RetransmitTimeoutMs  = IKE_Config.Connections->RetransmitTimeout;
    context->RetransmitRemainTick = 0u;
    context->ConnStatus           = IKE_CONN_INIT_RCVD;
    context->MessageId++;
    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/* ======================== ICV verify and SK decrypt===================== */

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_IkeVerifyIcvAuthResp(IkeConnContext* context, const uint8* ikeMsgStart, uint32 ikeLen)
{
    Std_ReturnType          Std_Return = E_NOT_OK;
    const uint8*            rxIcv      = ikeMsgStart - IKE_IKE_SPI_LEN + ikeLen - context->IntegOutputLen;
    Crypto_VerifyResultType Icv_Result;

    uint32 integVerifyJobId = IKE_Config.Transforms->IntegTransform[context->IntegTransformPbCfgId].VerifyJobId;
    uint32 integVerifyKeyId = IKE_Config.Transforms->IntegTransform[context->IntegTransformPbCfgId].VerifyKeyId;

    Std_Return = Csm_KeyElementSet(integVerifyKeyId, CRYPTO_KE_CIPHER_KEY, context->SK_ar, context->IntegKeyLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(integVerifyKeyId);

    Std_Return = Csm_MacVerify(
        integVerifyJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        ikeMsgStart - IKE_IKE_SPI_LEN,
        ikeLen - context->IntegOutputLen,
        rxIcv,
        context->IntegOutputLen,
        &Icv_Result);
    if (E_OK != Std_Return || Icv_Result == 1)
    {
        return E_NOT_OK;
    }

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_IkeDecryptSkAuthResp(
    IkeConnContext* context,
    uint8*          IVstart,
    uint8*          cipherStart,
    uint32          cipherlen,
    uint8*          plainStart,
    uint32*         plainOutLen)
{
    uint8                        outputData[IKE_IN_BUFFER_LEN] = {0};
    const uint8*                 encrKey                       = context->SK_er;
    const IKE_EncrTransformType* EncrTransformPtr =
        &IKE_Config.Transforms->EncrTransform[context->EncrTransformPbCfgId];
    uint32 decrKeyId = EncrTransformPtr->DecryptKeyId;

    Std_ReturnType Std_Return = Csm_KeyElementSet(decrKeyId, CRYPTO_KE_CIPHER_KEY, encrKey, context->EncrKeyLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    Std_Return = Csm_KeyElementSet(decrKeyId, CRYPTO_KE_CIPHER_IV, IVstart, IKE_IV_LEN);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(decrKeyId);

    uint32 outLen    = IKE_IN_BUFFER_LEN;
    uint32 decrJobId = EncrTransformPtr->DecryptJobId;
    Std_Return       = Csm_Decrypt(
        decrJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        (const uint8*)cipherStart,
        cipherlen,
        outputData,
        &outLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    /* should be modified by CSM, but CSM didn't do that */
    outLen = cipherlen;

    /* remove padding */
    uint8 padLen = outputData[outLen - 1u];
    if ((uint32)padLen + 1u > outLen)
    {
        return E_NOT_OK;
    }

    IStdLib_MemCpy(plainStart, outputData, outLen);
    *plainOutLen = outLen - 1u - (uint32)padLen;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeParseSa2Proposal(TcpIp_IpSecSAType* childSA, const uint8* parsePtr)
{
    uint8 nextPayload = 0;
    uint8 spiSize     = parsePtr[6];
    parsePtr += 8;

    if (0 == spiSize)
    {
        return E_NOT_OK;
    }

    IStdLib_MemCpy(childSA->InboundSpi, parsePtr, spiSize);
    parsePtr += spiSize;

    do
    {
        nextPayload = parsePtr[0];

        uint16 payloadLen    = (uint16)((parsePtr[2] << 8) | parsePtr[3]);
        uint8  transformType = parsePtr[4];
        uint16 transformId   = (uint16)((parsePtr[6] << 8) | parsePtr[7]);

        parsePtr += payloadLen;

        switch (transformType)
        {
        case TRANSFORM_ALGO_INTEG:
            for (uint32 i = 0; i < TCPIP_INTEGRITY_ALGO_NUMBER; i++)
            {
                if (TcpIp_IpSecPbCfg.IntegrityAlgorithmPtr[i].IntegrityTransformId == transformId)
                {
                    childSA->IntegrityAlgorithmListId = i;
                    switch (transformId)
                    {
                    case IKE_TRANSFORM_AUTH_HMAC_SHA1_96:
                        childSA->IntegKeyLen    = IKE_HMAC_SHA1_KEY_LEN;
                        childSA->IntegOutputLen = IKE_HMAC_SHA1_96_OUTPUT_LEN;
                        break;
                    case IKE_TRANSFORM_AUTH_HMAC_SHA2_256_128:
                        childSA->IntegKeyLen    = IKE_HMAC_SHA2_256_KEY_LEN;
                        childSA->IntegOutputLen = IKE_HMAC_SHA2_256_128_OUTPUT_LEN;
                        break;
                    case IKE_TRANSFORM_AUTH_HMAC_SHA2_384_192:
                        childSA->IntegKeyLen    = IKE_HMAC_SHA2_384_KEY_LEN;
                        childSA->IntegOutputLen = IKE_HMAC_SHA1_384_192_OUTPUT_LEN;
                        break;
                    case IKE_TRANSFORM_AUTH_HMAC_SHA2_512_256:
                        childSA->IntegKeyLen    = IKE_HMAC_SHA2_512_KEY_LEN;
                        childSA->IntegOutputLen = IKE_HMAC_SHA1_512_256_OUTPUT_LEN;
                        break;
                    default:
                        break;
                    }

                    break;
                }
            }
            break;

        case TRANSFORM_ALGO_ESN:
            break;

        case TRANSFORM_ALGO_ENCR:
            break;

        default:
            break;
        }
    } while (TRANSFORM_LAST_SUBSTRUC != nextPayload);

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_IkeParseTs(TcpIp_IpSecSAType* childSA, IkeRoleType role, const uint8* parsePtr)
{
    uint8 TSNum = parsePtr[0];
    parsePtr += 4;

    while (TSNum)
    {
        uint16 selectorLen = (uint16)((parsePtr[2] << 8) | parsePtr[3]);
        if ((IKE_TS_IPV4_ADDR_RANGE != parsePtr[0]) || (16 != selectorLen))
        {
            continue;
        }

        childSA->Protocol = parsePtr[1];
        parsePtr += 4;

        uint16 startPort = TCPIP_CHANGEPARAMETER_DECODE_U16(parsePtr);
        parsePtr += 2;

        uint16 endPort = TCPIP_CHANGEPARAMETER_DECODE_U16(parsePtr);
        parsePtr += 2;

        uint32 startAddr = 0;
        TcpIp_IkeCopyU32(&startAddr, parsePtr);
        parsePtr += 4u;

        uint32 endAddr = 0;
        TcpIp_IkeCopyU32(&endAddr, parsePtr);
        parsePtr += 4u;

        if (IKE_INITIATOR == role)
        {
            childSA->LocalPortRangeStart = startPort;
            childSA->LocalPortRangeEnd   = endPort;
            childSA->LocalIpAddrStart    = startAddr;
            childSA->LocalIpAddrEnd      = endAddr;
        }
        else
        {
            childSA->RemPortRangeStart = startPort;
            childSA->RemPortRangeEnd   = endPort;
            childSA->RemIpAddrStart    = startAddr;
            childSA->RemIpAddrEnd      = endAddr;
        }

        TSNum--;
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType TcpIp_IkeInstallSA(TcpIp_IpSecSAType* childSA)
{
    for (uint32 i = 0; i < TCPIP_SPD_NUMBER; i++)
    {
        if ((childSA->RemPortRangeStart >= TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemPortRangeStart)
            && (childSA->RemPortRangeEnd <= TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemPortRangeEnd)
            && (childSA->LocalPortRangeStart >= TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalPortRangeStart)
            && (childSA->LocalPortRangeEnd <= TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalPortRangeEnd)
            && (childSA->RemIpAddrStart >= TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemIpAddrStart)
            && (childSA->RemIpAddrEnd <= TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemIpAddrEnd)
            && (childSA->LocalIpAddrStart >= TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalIpAddrStart)
            && (childSA->LocalIpAddrEnd <= TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalIpAddrEnd)
            && (childSA->HeaderType == TcpIp_IpSecPbCfg.SpdEntryPtr[i].HeaderType))
        {
            if ((IP_PROTO_ANY != TcpIp_IpSecPbCfg.SpdEntryPtr[i].Protocol)
                && (childSA->PolicyType != TcpIp_IpSecPbCfg.SpdEntryPtr[i].Protocol))
            {
                continue;
            }
            childSA->PolicyType = TcpIp_IpSecPbCfg.SpdEntryPtr[i].PolicyType;
            return E_OK;
        }
    }

    return E_NOT_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
TCPIP_LOCAL Std_ReturnType
    TcpIp_IkeParseSkPlainAuthResp(IkeConnContext* context, const uint8* innerPtr, uint32 innerLen, uint8 innerNext)
{
    uint32             remain  = innerLen;
    TcpIp_IpSecSAType* childSA = TcpIp_IkeFindInboundChildSA(context);
    if (NULL_PTR == childSA)
    {
        return E_NOT_OK;
    }

    while ((innerNext != IKE_NEXT_PAYLOAD_TYPE_NONE) && (remain >= IKE_PAYLOAD_HEADER_LEN))
    {
        uint8        curType = innerNext;
        const uint8* curHdr  = innerPtr;

        /* get payload type */
        innerNext     = curHdr[0];
        uint16 curLen = (uint16)((curHdr[2] << 8) | curHdr[3]);

        if ((curLen < 4u) || (curLen > remain))
        {
            TcpIp_IkeRollbackChildSA(context, childSA);
            return E_NOT_OK;
        }

        const uint8* bodyPtr = curHdr + IKE_PAYLOAD_HEADER_LEN;
        uint16       bodyLen = (uint16)(curLen - IKE_PAYLOAD_HEADER_LEN);
        if (bodyLen < 4u)
        {
            TcpIp_IkeRollbackChildSA(context, childSA);
            return E_NOT_OK;
        }

        switch (curType)
        {
        case IKE_NEXT_PAYLOAD_TYPE_IDR:
        {
            uint8 idType = bodyPtr[0];
            (void)idType;
            break;
        }

        case IKE_NEXT_PAYLOAD_TYPE_AUTH:
        {
            uint8 method = bodyPtr[0];
            (void)method;
            break;
        }

        case IKE_NEXT_PAYLOAD_TYPE_SA:
        {
            TcpIp_IkeParseSa2Proposal(childSA, bodyPtr);
            break;
        }

        case IKE_NEXT_PAYLOAD_TYPE_TSI:
        {
            TcpIp_IkeParseTs(childSA, IKE_INITIATOR, bodyPtr);
            break;
        }

        case IKE_NEXT_PAYLOAD_TYPE_TSR:
        {
            TcpIp_IkeParseTs(childSA, IKE_RESPONDER, bodyPtr);
            break;
        }

        default:
            break;
        }

        innerPtr += curLen;
        remain -= curLen;
    }

    Std_ReturnType Std_Return = TcpIp_IkeInstallSA(childSA);
    if (Std_Return != E_OK)
    {
        TcpIp_IkeRollbackChildSA(context, childSA);
        return Std_Return;
    }

    Ipsec_ChildSaKeysGenerate(context, childSA);

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

/* ====================== entrance: Ike AUTH parse (parse ICV) ====================== */

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeParseAuth(IkeConnContext* context, uint8* parsePtr)
{
    Std_ReturnType Std_Return = E_OK;
    uint8*         ikeStart   = parsePtr;

    /* compare ResponderSPI */
    if (0 != IStdLib_MemCmp(parsePtr, context->ResponderSPI, IKE_IKE_SPI_LEN))
    {
        return E_OK;
    }
    parsePtr += IKE_IKE_SPI_LEN;

    uint8 nextPayload = parsePtr[0];
    if (nextPayload != IKE_NEXT_PAYLOAD_TYPE_SK)
    {
        return E_OK;
    }
    parsePtr++;

    if (IKE_VERSION_2 != parsePtr[0])
    {
        return E_OK;
    }
    parsePtr++;

    if (IKE_EXCHANGE_TYPE_AUTH != parsePtr[0])
    {
        return E_OK;
    }
    /* skip Flags */
    parsePtr += 2u;

    /* Message ID */
    uint32 messageId = TCPIP_CHANGEPARAMETER_DECODE_U32(parsePtr);
    if (messageId < context->PeerMessageId)
    {
        return E_OK;
    }
    context->PeerMessageId = messageId;
    parsePtr += 4u;

    uint32 ikeLen = TCPIP_CHANGEPARAMETER_DECODE_U32(parsePtr);
    parsePtr += 4u;

    /* calculate IKE start for ICV check */
    Std_Return = TcpIp_IkeVerifyIcvAuthResp(context, ikeStart, ikeLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    /*** now parsePtr point to SK payload ***/
    uint8 firstPayload = parsePtr[0];
    parsePtr += 2;

    uint16 skLen = TCPIP_CHANGEPARAMETER_DECODE_U16(parsePtr);
    parsePtr += 2;

    uint8* IVStart = parsePtr;
    parsePtr += IKE_IV_LEN;

    /*** now parsePtr point to decypted data ***/
    /* decrypt SK */
    uint32 plainLen  = 0u;
    uint32 cipherLen = skLen - IKE_PAYLOAD_HEADER_LEN - IKE_IV_LEN - context->IntegOutputLen;
    Std_Return       = TcpIp_IkeDecryptSkAuthResp(context, IVStart, parsePtr, cipherLen, parsePtr, &plainLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    /* parse SK plain payload chain(IDr/AUTH/SA/TSi/TSr/...) */
    Std_Return = TcpIp_IkeParseSkPlainAuthResp(context, parsePtr, plainLen, firstPayload);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    context->ConnStatus = IKE_CONN_ESTABLISHED;
    context->MessageId++;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_IkeRxIndication(
    TcpIp_SocketIdType        SocketId,
    const TcpIp_SockAddrType* RemoteAddrPtr,
    const uint8*              BufPtr,
    uint16                    Length)
{
    IkeConnContext* context    = NULL;
    Std_ReturnType  Std_Return = E_OK;

    for (uint32 i = 0; i < IKE_CONNECTION_NUMBER; i++)
    {
        if (SocketId == IkeConnContextTable[i].SocketId)
        {
            context = &IkeConnContextTable[i];
            break;
        }
    }

    if ((NULL == context) || (Length < IKE_HEADER_LEN))
    {
        return;
    }

    const uint8* parsePtr     = BufPtr;
    const uint8* ikeLengthPtr = &parsePtr[24];
    uint32       ikeLength    = TCPIP_CHANGEPARAMETER_DECODE_U32(ikeLengthPtr);

    if (ikeLength != Length)
    {
        return;
    }

    /* compare InitiatorSPI */
    if (0 != IStdLib_MemCmp(parsePtr, context->InitiatorSPI, IKE_IKE_SPI_LEN))
    {
        return;
    }
    parsePtr += IKE_IKE_SPI_LEN;

    /* now parsePtr point at responder SPI */
    switch (context->ConnStatus)
    {
    case IKE_CONN_INIT_SENT:
        Std_Return = TcpIp_IkeParseSaInit(context, parsePtr);
        break;

    case IKE_CONN_AUTH_SENT:
        Std_Return = TcpIp_IkeParseAuth(context, (uint8*)parsePtr);
        break;

    default:
        break;
    }

    if (Std_Return != E_OK)
    {
        // send notify
    }

    return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build SA1 payload.
 * @param[in]	context   : IKE context pointer.
                bufPtr    : ptr to the buffer.
 * @return		void.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
void TcpIp_IkeBuildSa1Payload(IkeConnContext* context, uint8** bufPtr)
{
    uint8* writePtr = *bufPtr;

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_KE;
    /* critical bit */
    writePtr[1] = 0;
    writePtr += 2u;

    /* calculate length later */
    uint8* saLengthPtr = writePtr;
    writePtr += 2u;

    /********************* proposal field**********************/

    /* next payload */
    writePtr[0] = IKE_NEXT_PAYLOAD_TYPE_NONE;
    /* reserved */
    writePtr[1] = 0;
    writePtr += 2u;

    /* calculate length later */
    uint8* proposalLengthPtr = writePtr;
    writePtr += 2u;

    /* proposal number */
    writePtr[0] = 1; /* only 1 proposal supported now */
    writePtr++;

    /*  Protocol ID */
    writePtr[0] = IPSEC_PROTOCOL_ID_IKE;
    writePtr++;

    /* SPI Size */
    writePtr[0] = 0;
    writePtr++;

    /* calculate transform number later */
    uint8* transformNumPtr = writePtr;
    writePtr++;

    /*** transform payload ***/
    /* Encryption */
    for (uint32 i = 0; i < IKE_ENCR_TRANSFORM_NUMBER; i++)
    {
        /* Last Substruc */
        writePtr[0] = TRANSFORM_NONE_LAST_SUBSTRUC;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        uint8* transformPayloadLengthPtr = writePtr;
        writePtr += 2u;

        /* Transform Type */
        writePtr[0] = TRANSFORM_ALGO_ENCR;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        /* Transform ID  */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, IKE_Config.Transforms->EncrTransform[i].TransformId);
        writePtr += 2u;

        /* Transform Attributes */
        Bfx_SetBit_u8u8(writePtr, IKE_TV_FORMAT_BIT); /* TV format */
        writePtr++;

        writePtr[0] = TRANSFORM_ATTRIBUTE_VALUE_KEY_LEN;
        writePtr++;

        /* key length, in bit */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, IKE_Config.Transforms->EncrTransform[i].KeyLength);
        writePtr += 2u;

        uint16 transformPayloadLength = writePtr - transformPayloadLengthPtr + 2u; /* including Header */
        TCPIP_CHG_PARA_ENCODE_16(transformPayloadLengthPtr, transformPayloadLength);

        (*transformNumPtr)++;
    }

    /* PRF */
    for (uint32 i = 0; i < IKE_PRF_TRANSFORM_NUMBER; i++)
    {
        /* Last Substruc */
        writePtr[0] = TRANSFORM_NONE_LAST_SUBSTRUC;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        uint8* transformPayloadLengthPtr = writePtr;
        writePtr += 2u;

        /* Transform Type */
        writePtr[0] = TRANSFORM_ALGO_PRF;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        /* Transform ID  */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, IKE_Config.Transforms->PrfTransform[i].TransformId);
        writePtr += 2u;

        uint16 transformPayloadLength = writePtr - transformPayloadLengthPtr + 2u; /* including Header */
        TCPIP_CHG_PARA_ENCODE_16(transformPayloadLengthPtr, transformPayloadLength);

        (*transformNumPtr)++;
    }

    /* Integrity */
    for (uint32 i = 0; i < IKE_INTEG_TRANSFORM_NUMBER; i++)
    {
        /* Last Substruc */
        writePtr[0] = TRANSFORM_NONE_LAST_SUBSTRUC;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        uint8* transformPayloadLengthPtr = writePtr;
        writePtr += 2u;

        /* Transform Type */
        writePtr[0] = TRANSFORM_ALGO_INTEG;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        /* Transform ID  */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, IKE_Config.Transforms->IntegTransform[i].TransformId);
        writePtr += 2u;

        uint16 transformPayloadLength = writePtr - transformPayloadLengthPtr + 2u; /* including Header */
        TCPIP_CHG_PARA_ENCODE_16(transformPayloadLengthPtr, transformPayloadLength);

        (*transformNumPtr)++;
    }

    /* KE(DH) */
    uint8* lastSubstrucPtr = NULL;
    for (uint32 i = 0; i < IKE_DH_TRANSFORM_NUMBER; i++)
    {
        /* Last Substruc */
        writePtr[0]     = TRANSFORM_NONE_LAST_SUBSTRUC;
        lastSubstrucPtr = writePtr;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        uint8* transformPayloadLengthPtr = writePtr;
        writePtr += 2u;

        /* Transform Type */
        writePtr[0] = TRANSFORM_ALGO_DH;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        /* Transform ID  */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, IKE_Config.Transforms->DhTransform[i].TransformId);
        writePtr += 2u;

        uint16 transformPayloadLength = writePtr - transformPayloadLengthPtr + 2u; /* including Header */
        TCPIP_CHG_PARA_ENCODE_16(transformPayloadLengthPtr, transformPayloadLength);

        (*transformNumPtr)++;
    }
    *lastSubstrucPtr = TRANSFORM_LAST_SUBSTRUC;

    uint16 proposalLength = writePtr - proposalLengthPtr + 2u;
    TCPIP_CHG_PARA_ENCODE_16(proposalLengthPtr, proposalLength);

    uint16 saLength = writePtr - saLengthPtr + 2u;
    TCPIP_CHG_PARA_ENCODE_16(saLengthPtr, saLength);

    *bufPtr = writePtr;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeRandomGenerateOnce(IkeConnContext* context, uint8* resultPtr, uint32* resultLengthPtr)
{
    Std_ReturnType Std_Return = E_OK;

    if (0 == context->RetransmitTries) /* Avoid repeated RandomGenerate */
    {
        uint32 randKeybId = IKE_Config.General->RandomKeyId;
        uint32 randJobId  = IKE_Config.General->RandomJobId;
        (void)Csm_KeySetValid(randKeybId);
        Std_Return = Csm_RandomGenerate(randJobId, CRYPTO_OPERATIONMODE_SINGLECALL, resultPtr, resultLengthPtr);
    }

    return Std_Return;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build SA2 payload.
 * @param[in]	context   : IKE context pointer.
                bufPtr    : ptr to the buffer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_Ike_BuildSa2Payload(IkeConnContext* context, uint8** bufPtr)
{
    Std_ReturnType Std_Return = E_OK;
    uint8*         writePtr   = *bufPtr;

    TcpIp_IpSecSAType* childSAPtr = TcpIp_IkeFindOutboundChildSA(context);
    if (NULL_PTR == childSAPtr)
    {
        return E_NOT_OK;
    }

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_TSI;
    /* critical bit */
    writePtr[1] = 0;
    writePtr += 2u;

    /* calculate length later */
    uint8* saLengthPtr = writePtr;
    writePtr += 2u;

    /********************* proposal field**********************/

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_NONE;
    /* reserved */
    writePtr[1] = 0;
    writePtr += 2u;

    /* calculate length later */
    uint8* proposalLengthPtr = writePtr;
    writePtr += 2u;

    /* proposal number */
    writePtr[0] = 1; /* only 1 proposal supported now */
    writePtr++;

    /*	Protocol ID */
    writePtr[0] = (uint8)IPSEC_PROTOCOL_ID_AH;
    writePtr++;

    /* SPI Size */
    writePtr[0] = (uint8)IKE_ESP_AH_SPI_LEN;
    writePtr++;

    /* calculate transform number later */
    uint8* transformNumPtr = writePtr;
    writePtr++;

    uint32 spiLen = IKE_ESP_AH_SPI_LEN;
    Std_Return    = TcpIp_IkeRandomGenerateOnce(context, childSAPtr->OutboundSpi, &spiLen);
    if (E_OK != Std_Return)
    {
        TcpIp_IkeRollbackChildSA(context, childSAPtr);
        return Std_Return;
    }
    IStdLib_MemCpy(writePtr, childSAPtr->OutboundSpi, IKE_ESP_AH_SPI_LEN);
    writePtr += IKE_ESP_AH_SPI_LEN;

    /*** transform payload ***/
    /* only Integrity needed for AH */
    for (uint32 i = 0; i < TCPIP_INTEGRITY_ALGO_NUMBER; i++)
    {
        /* Non Last Substruc */
        writePtr[0] = (uint8)TRANSFORM_NONE_LAST_SUBSTRUC;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        /* calculate length later */
        uint8* transformPayloadLengthPtr = writePtr;
        writePtr += 2u;

        /* Transform Type */
        writePtr[0] = (uint8)TRANSFORM_ALGO_INTEG;
        writePtr++;

        /* RESERVED */
        writePtr[0] = 0;
        writePtr++;

        /* Transform ID  */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, TcpIp_IpSecPbCfg.IntegrityAlgorithmPtr[i].IntegrityTransformId);
        writePtr += 2u;

        uint16 transformPayloadLength = writePtr - transformPayloadLengthPtr + 2u; /* including Header */
        TCPIP_CHG_PARA_ENCODE_16(transformPayloadLengthPtr, transformPayloadLength);

        (*transformNumPtr)++;
    }

    /**** ESN ****/
    /* Last Substruc */
    writePtr[0] = (uint8)TRANSFORM_LAST_SUBSTRUC;
    writePtr++;

    /* RESERVED */
    writePtr[0] = 0;
    writePtr++;

    /* length */
    TCPIP_CHG_PARA_ENCODE_16(writePtr, 8);
    writePtr += 2u;

    /* Transform Type */
    writePtr[0] = (uint8)TRANSFORM_ALGO_ESN;
    writePtr++;

    /* RESERVED */
    writePtr[0] = 0;
    writePtr++;

    /* Transform ID  */
    TCPIP_CHG_PARA_ENCODE_16(writePtr, 0); /* no extended seq number */
    writePtr += 2u;

    (*transformNumPtr)++;
    /**** ESN end ****/

    uint16 proposalLength = writePtr - proposalLengthPtr + 2u;
    TCPIP_CHG_PARA_ENCODE_16(proposalLengthPtr, proposalLength);

    uint16 saLength = writePtr - saLengthPtr + 2u;
    TCPIP_CHG_PARA_ENCODE_16(saLengthPtr, saLength);

    *bufPtr = writePtr;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build KE payload.
 * @param[in]	context   : IKE context pointer.
                bufPtr    : ptr to the buffer.
 * @return		void.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_IkeBuildKEPayload(IkeConnContext* context, uint8** bufPtr)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint8*         writePtr   = *bufPtr;
    uint32         dhKeyId    = IKE_Config.Transforms->DhTransform[0].KeyId;

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_NONCE;
    writePtr[1] = 0; /* critical bit */
    writePtr += 2u;

    /* calculate length later */
    uint8* keLengthPtr = writePtr;
    writePtr += 2u;

    /* DH group */
    TCPIP_CHG_PARA_ENCODE_16(writePtr, IKE_Config.Transforms->DhTransform[0].TransformId);
    writePtr += 2u;

    /* RESERVED */
    writePtr[0] = 0;
    writePtr[1] = 0;
    writePtr += 2u;

    uint8  dhPublicKey[IKE_DH_KEY_MAX_LEN] = {0};
    uint32 dhPublicKeyLen                  = IKE_DH_KEY_MAX_LEN;
    context->DHKeyLen                      = 32;

    Std_Return = Csm_KeySetValid(dhKeyId);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

#if (TLS_USE_CSM_API == STD_ON)
    /* Generate private key */
    Std_Return = Csm_KeyGenerate(dhKeyId);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
#endif
    Std_Return = Csm_KeyExchangeCalcPubVal(dhKeyId, dhPublicKey, &dhPublicKeyLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    IStdLib_MemCpy(writePtr, dhPublicKey, context->DHKeyLen);
    writePtr += context->DHKeyLen;

    uint16 keLength = writePtr - keLengthPtr + 2u;
    TCPIP_CHG_PARA_ENCODE_16(keLengthPtr, keLength);

    *bufPtr = writePtr;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build IDi payload.
 * @param[in]	IkeConnIdx   : IKE context index.
                bufPtr    : ptr to the buffer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_Ike_BuildIDiPayload(uint32 IkeConnIdx, uint8** bufPtr)
{
    const IKE_ConnectionType* conn     = &IKE_Config.Connections->Connection[IkeConnIdx];
    IkeConnContext*           context  = &IkeConnContextTable[IkeConnIdx];
    uint8*                    writePtr = *bufPtr;

    /* NextPayload = AUTH */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_IDR;
    writePtr[1] = 0; /* critical bit */
    writePtr += 2u;

    /* calculate length later */
    uint8* lenPtr = writePtr;
    writePtr += 2u;

    uint8* SignedOctetsPtr = writePtr;

    writePtr[0] = (uint8)IKE_ID_IPV4_ADDR; /* ID type */
    writePtr[1] = 0u;                      /* RESERVED */
    writePtr[2] = 0u;                      /* RESERVED */
    writePtr[3] = 0u;                      /* RESERVED */
    writePtr += 4u;

    TcpIp_SockAddrType IpAddr = {.domain = TCPIP_AF_INET};
    uint8              Netmask;
    TcpIp_SockAddrType DefaultRouter = {.domain = TCPIP_AF_INET};
    Std_ReturnType     Std_Return    = TcpIp_GetIpAddr(conn->LocalAddressId, &IpAddr, &Netmask, &DefaultRouter);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    IStdLib_MemCpy(writePtr, &IpAddr.addr, 4u);
    writePtr += 4u;

    uint16 idLen = (uint16)(writePtr - lenPtr + 2u);
    TCPIP_CHG_PARA_ENCODE_16(lenPtr, idLen);

    const IKE_PrfTransformType* prfTransformPtr = &IKE_Config.Transforms->PrfTransform[context->PrfTransformPbCfgId];
    uint32                      prfJobId        = prfTransformPtr->JobId;
    uint32                      prfKeyId        = prfTransformPtr->KeyId;
    Std_Return = Csm_KeyElementSet(prfKeyId, CRYPTO_KE_CIPHER_KEY, context->SK_pi, context->PrfKeyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(prfKeyId);

    uint32 MACedIDForILen                      = IKE_PRF_OUTPUT_MAX_LEN;
    uint8  MACedIDForI[IKE_PRF_OUTPUT_MAX_LEN] = {0};
    Std_Return                                 = Csm_MacGenerate(
        prfJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        SignedOctetsPtr,
        idLen - 4,
        MACedIDForI,
        &MACedIDForILen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    IStdLib_MemCpy(
        &context->InitiatorSignedOctets[context->RealMessage1Len + context->ResponderNonceLen],
        MACedIDForI,
        MACedIDForILen);
    context->macedIDLen = MACedIDForILen;

    *bufPtr = writePtr;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build IDr payload.
 * @param[in]	IkeConnIdx   : IKE context index.
                bufPtr    : ptr to the buffer.
 * @return		void.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
void TcpIp_Ike_BuildIDrPayload(uint32 IkeConnIdx, uint8** bufPtr)
{
    const IKE_ConnectionType* conn     = &IKE_Config.Connections->Connection[IkeConnIdx];
    uint8*                    writePtr = *bufPtr;

    /* NextPayload = AUTH */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_AUTH;
    writePtr[1] = 0; /* critical bit */
    writePtr += 2u;

    /* calculate length later */
    uint8* lenPtr = writePtr;
    writePtr += 2u;

    writePtr[0] = (uint8)IKE_ID_IPV4_ADDR; /* ID type */
    writePtr[1] = 0u;                      /* RESERVED */
    writePtr[2] = 0u;                      /* RESERVED */
    writePtr[3] = 0u;                      /* RESERVED */
    writePtr += 4u;

    IStdLib_MemCpy(writePtr, &conn->RemoteAddress, 4u);
    writePtr += 4u;

    uint16 idLen = (uint16)(writePtr - lenPtr + 2u);
    TCPIP_CHG_PARA_ENCODE_16(lenPtr, idLen);

    *bufPtr = writePtr;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build AUTH payload.
 * @param[in]	context   : IKE context pointer.
                bufPtr    : ptr to the buffer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_IkeBuildAuthPayload(IkeConnContext* context, uint8** bufPtr, uint32 IkeConnIdx)
{
    uint8* writePtr = *bufPtr;

    /* NextPayload Child SA  */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_NOTIFY;
    writePtr[1] = 0; /* critical bit */
    writePtr += 2u;

    /* calculate length later */
    uint8* lenPtr = writePtr;
    writePtr += 2u;

    /* AUTH Method: 2 = Shared Key Message Integrity Code (PSK) */
    writePtr[0] = IKE_AUTH_METHOD_PSK; /* AUTH method */
    writePtr[1] = 0u;                  /* RESERVED */
    writePtr[2] = 0u;                  /* RESERVED */
    writePtr[3] = 0u;                  /* RESERVED */
    writePtr += 4u;

    uint32 pskKeyId = IKE_Config.Connections->Connection[IkeConnIdx].ECUPreSharedKeyId;

    const IKE_PrfTransformType* prfTransformPtr = &IKE_Config.Transforms->PrfTransform[context->PrfTransformPbCfgId];
    uint32                      prfJobId        = prfTransformPtr->JobId;
    uint32                      prfKeyId        = prfTransformPtr->KeyId;
    uint32                      pskKeyLen       = IKE_PSK_KEY_MAX_LEN;
    uint8                       pskKey[IKE_PSK_KEY_MAX_LEN] = {0};
    /* calculate pad key */
    (void)Csm_KeySetValid(pskKeyId);
    Std_ReturnType Std_Return = Csm_KeyElementGet(pskKeyId, CRYPTO_KE_CIPHER_KEY, pskKey, &pskKeyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    Std_Return = Csm_KeyElementSet(prfKeyId, CRYPTO_KE_CIPHER_KEY, pskKey, pskKeyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(prfKeyId);

    uint32 padKeyLen                      = IKE_PRF_OUTPUT_MAX_LEN;
    uint8  padKey[IKE_PRF_OUTPUT_MAX_LEN] = {0};
    Std_Return                            = Csm_MacGenerate(
        prfJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        (const uint8*)IKE_LABEL_KEY_PAD,
        CONST_STRLEN(IKE_LABEL_KEY_PAD),
        padKey,
        &padKeyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    /* calculate Authentication Data */
    Std_Return = Csm_KeyElementSet(prfKeyId, CRYPTO_KE_CIPHER_KEY, padKey, padKeyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(prfKeyId);

    uint32 authDataLen                      = IKE_PRF_OUTPUT_MAX_LEN;
    uint8  authData[IKE_PRF_OUTPUT_MAX_LEN] = {0};
    Std_Return                              = Csm_MacGenerate(
        prfJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        context->InitiatorSignedOctets,
        context->RealMessage1Len + context->ResponderNonceLen + context->macedIDLen,
        authData,
        &authDataLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    /* Authentication Data */
    IStdLib_MemCpy(writePtr, authData, authDataLen);
    writePtr += authDataLen;

    uint16 authLen = (uint16)(writePtr - lenPtr + 2u);
    TCPIP_CHG_PARA_ENCODE_16(lenPtr, authLen);

    *bufPtr = writePtr;
    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build Notify payload.
 * @param[in]	context   : IKE context pointer.
                bufPtr    : ptr to the buffer.
                notifyType: notify type.
 * @return		void.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
void TcpIp_IkeBuildNotifyPayload(IkeConnContext* context, uint8** bufPtr, uint16 notifyType)
{
    uint8* writePtr = *bufPtr;

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_SA;
    /* critical bit */
    writePtr[1] = 0;
    writePtr += 2u;

    /* length */
    TCPIP_CHG_PARA_ENCODE_16(writePtr, 8);
    writePtr += 2u;

    writePtr[0] = 0; /* RESERVED */
    writePtr[1] = 0; /* SPI size */
    writePtr += 2u;

    TCPIP_CHG_PARA_ENCODE_16(writePtr, notifyType);
    writePtr += 2u;

    *bufPtr = writePtr;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build TSi and TSr payload.
 * @param[in]	context   : IKE context pointer.
                bufPtr    : ptr to the buffer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
void TcpIp_IkeBuildTsPayload(IkeConnContext* context, uint8** bufPtr)
{
    uint8* writePtr = *bufPtr;

    /* ---------- TSi ---------- */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_TSR; /* next payload TSr */
    writePtr[1] = 0;                                /* critical bit */
    writePtr += 2u;

    /* calculate length later */
    uint8* tsiLenPtr = writePtr;
    writePtr += 2u;

    /* #TS = 1, RESERVED=0 */
    writePtr[0] = TCPIP_SPD_NUMBER; /* TS number */
    writePtr[1] = 0u;               /* RESERVED */
    writePtr[2] = 0u;               /* RESERVED */
    writePtr[3] = 0u;               /* RESERVED */
    writePtr += 4u;

    /* Traffic Selector */
    for (uint32 i = 0; i < TCPIP_SPD_NUMBER; i++)
    {
        writePtr[0] = IKE_TS_IPV4_ADDR_RANGE;
        writePtr[1] = TcpIp_IpSecPbCfg.SpdEntryPtr[i].Protocol; /* protocol id */
        writePtr += 2;

        /* Selector len */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, 16u);
        writePtr += 2u;

        /* start port */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalPortRangeStart);
        writePtr += 2u;

        /* end port */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalPortRangeEnd);
        writePtr += 2u;

        /* IPv4 start */
        IStdLib_MemCpy(writePtr, &TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalIpAddrStart, 4u);
        writePtr += 4u;

        /* IPv4 end */
        IStdLib_MemCpy(writePtr, &TcpIp_IpSecPbCfg.SpdEntryPtr[i].LocalIpAddrEnd, 4u);
        writePtr += 4u;
    }

    uint16 tsiLen = (uint16)(4u + 4u + TCPIP_SPD_NUMBER * 16u);
    TCPIP_CHG_PARA_ENCODE_16(tsiLenPtr, tsiLen);

    /* ---------- TSr ---------- */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_NONE; /* next payload none */
    writePtr[1] = 0;                                 /* critical bit */
    writePtr += 2u;

    /* calculate length later */
    tsiLenPtr = writePtr;
    writePtr += 2u;

    /* #TS = 1, RESERVED=0 */
    writePtr[0] = TCPIP_SPD_NUMBER; /* TS number */
    writePtr[1] = 0u;               /* RESERVED */
    writePtr[2] = 0u;               /* RESERVED */
    writePtr[3] = 0u;               /* RESERVED */
    writePtr += 4u;

    /* Traffic Selector */
    for (uint32 i = 0; i < TCPIP_SPD_NUMBER; i++)
    {
        writePtr[0] = IKE_TS_IPV4_ADDR_RANGE;
        writePtr[1] = TcpIp_IpSecPbCfg.SpdEntryPtr[i].Protocol; /* protocol id */
        writePtr += 2u;

        /* Selector len */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, 16u);
        writePtr += 2u;

        /* start port */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemPortRangeStart);
        writePtr += 2u;

        /* end port */
        TCPIP_CHG_PARA_ENCODE_16(writePtr, TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemPortRangeEnd);
        writePtr += 2u;

        /* IPv4 start */
        IStdLib_MemCpy(writePtr, &TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemIpAddrStart, 4u);
        writePtr += 4u;

        /* IPv4 end */
        IStdLib_MemCpy(writePtr, &TcpIp_IpSecPbCfg.SpdEntryPtr[i].RemIpAddrEnd, 4u);
        writePtr += 4u;
    }

    tsiLen = (uint16)(4u + 4u + TCPIP_SPD_NUMBER * 16u);
    TCPIP_CHG_PARA_ENCODE_16(tsiLenPtr, tsiLen);

    *bufPtr = writePtr;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build Nonce payload.
 * @param[in]	context   : IKE context pointer.
                bufPtr    : ptr to the buffer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_IkeBuildNoncePayload(IkeConnContext* context, uint8** bufPtr)
{
    uint8*         writePtr   = *bufPtr;
    Std_ReturnType Std_Return = E_NOT_OK;

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_NONE;
    /* critical bit */
    writePtr[1] = 0;
    writePtr += 2u;

    /* calculate length later */
    uint8* nonceLengthPtr = writePtr;
    writePtr += 2u;

    uint32 nonceLen = IKE_NONCE_LEN;
    Std_Return      = TcpIp_IkeRandomGenerateOnce(context, context->InitiatorNonce, &nonceLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    IStdLib_MemCpy(writePtr, context->InitiatorNonce, IKE_NONCE_LEN);
    writePtr += IKE_NONCE_LEN;

    uint16 nonceLength = writePtr - nonceLengthPtr + 2u;
    TCPIP_CHG_PARA_ENCODE_16(nonceLengthPtr, nonceLength);

    *bufPtr = writePtr;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build IKE_SA_INIT packet.
 * @param[in]	context   : IKE context pointer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_IkeBuildSaInit(IkeConnContext* context)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint8*         writePtr   = context->outPBuf->payload;
    uint32         spiLen     = IKE_IKE_SPI_LEN;

    IStdLib_MemSet(context->outPBuf->payload, 0, context->outPBuf->len);

    Std_Return = TcpIp_IkeRandomGenerateOnce(context, context->InitiatorSPI, &spiLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    IStdLib_MemCpy(writePtr, context->InitiatorSPI, IKE_IKE_SPI_LEN);
    writePtr += IKE_IKE_SPI_LEN;

    /* responder SPI */
    IStdLib_MemSet(writePtr, 0, IKE_IKE_SPI_LEN);
    writePtr += IKE_IKE_SPI_LEN;

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_SA;
    writePtr += 1u;

    /* version */
    writePtr[0] = (uint8)IKE_VERSION_2;
    writePtr += 1u;

    /* exchange type */
    writePtr[0] = (uint8)IKE_EXCHANGE_TYPE_SA_INIT;
    writePtr += 1u;

    /* Flags, Initiator bit set */
    Bfx_SetBit_u8u8(writePtr, IKE_INITIATOR_BIT);
    Bfx_ClrBit_u8u8(writePtr, IKE_VERSION_BIT);
    Bfx_ClrBit_u8u8(writePtr, IKE_RESPONDER_BIT);
    writePtr += 1u;

    /* message id */
    TCPIP_CHG_PARA_ENCODE_32(writePtr, context->MessageId);
    writePtr += 4u;

    /* calculate length later */
    uint8* lengthPtr = writePtr;
    writePtr += 4u;

    /* SA payload */
    TcpIp_IkeBuildSa1Payload(context, &writePtr);

    /* KE payload */
    TcpIp_IkeBuildKEPayload(context, &writePtr);

    /* Nonce payload */
    Std_Return = TcpIp_IkeBuildNoncePayload(context, &writePtr);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    uint32 length = writePtr - (uint8*)context->outPBuf->payload;
    TCPIP_CHG_PARA_ENCODE_32(lengthPtr, length);

    context->outContentLength = length;

    IStdLib_MemCpy(&context->InitiatorSignedOctets, context->outPBuf->payload, length);
    context->RealMessage1Len = length;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Encrypt and Integrity calculation.
 * @param[in]	context   : IKE context pointer.
                dataPtr   : pointer to data.
                dataLenPtr: length of data, modified after caculation.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_IkeEncrypt(IkeConnContext* context, uint8* dataPtr, uint32* dataLenPtr)
{
    Std_ReturnType Std_Return                    = E_NOT_OK;
    const uint32   block                         = 16u;
    uint8          inputData[IKE_OUT_BUFFER_LEN] = {0};
    uint32         encrKeyId = IKE_Config.Transforms->EncrTransform[context->EncrTransformPbCfgId].EncryptKeyId;
    uint32         encrJobId = IKE_Config.Transforms->EncrTransform[context->EncrTransformPbCfgId].EncryptJobId;

    uint32 innerLen   = *dataLenPtr;
    uint32 padLen     = (block - ((innerLen + 1u) % block)) % block; /* +1 reserve PadLen */
    uint32 totalPlain = innerLen + padLen + 1u;

    IStdLib_MemCpy(inputData, dataPtr, innerLen);
    IStdLib_MemSet(inputData + innerLen, 0u, padLen);
    inputData[innerLen + padLen] = (uint8)padLen;

    Std_Return = Csm_KeyElementSet(encrKeyId, CRYPTO_KE_CIPHER_KEY, context->SK_ei, context->EncrKeyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }
    Std_Return = Csm_KeyElementSet(encrKeyId, CRYPTO_KE_CIPHER_IV, context->IV, IKE_IV_LEN);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(encrKeyId);

    *dataLenPtr = totalPlain;
    Std_Return  = Csm_Encrypt(encrJobId, CRYPTO_OPERATIONMODE_SINGLECALL, inputData, totalPlain, dataPtr, dataLenPtr);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IPSecICVGenerate(
    TcpIp_IpSecSAType* spd_entry,
    uint8*             keyPtr,
    uint32             keyLen,
    uint8*             dataPtr,
    uint32             dataLen,
    uint8*             resultPtr,
    uint32*            resultLenPtr)
{
    Std_ReturnType Std_Return = E_NOT_OK;
    uint32         integJobId = TcpIp_IpSecPbCfg.IntegrityAlgorithmPtr[spd_entry->IntegrityAlgorithmListId]
                            .IntegrityTransformJobPair[0]
                            .CsmGenerateJobId;
    uint32 integKeyId = TcpIp_IpSecPbCfg.IntegrityAlgorithmPtr[spd_entry->IntegrityAlgorithmListId]
                            .IntegrityTransformJobPair[0]
                            .CsmGenerateKeyId;

    Std_Return = Csm_KeyElementSet(integKeyId, CRYPTO_KE_CIPHER_KEY, keyPtr, keyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(integKeyId);

    Std_Return =
        Csm_MacGenerate(integJobId, CRYPTO_OPERATIONMODE_SINGLECALL, dataPtr, dataLen, resultPtr, resultLenPtr);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeICVGenerate(IkeConnContext* context)
{
    uint8  macFull[IKE_PRF_OUTPUT_MAX_LEN] = {0};
    uint32 macLen                          = IKE_PRF_OUTPUT_MAX_LEN;
    uint32 integJobId = IKE_Config.Transforms->IntegTransform[context->IntegTransformPbCfgId].GenerateJobId;
    uint32 integKeyId = IKE_Config.Transforms->IntegTransform[context->IntegTransformPbCfgId].GenerateKeyId;

    Std_ReturnType Std_Return =
        Csm_KeyElementSet(integKeyId, CRYPTO_KE_CIPHER_KEY, context->SK_ai, context->IntegKeyLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }
    (void)Csm_KeySetValid(integKeyId);

    Std_Return = Csm_MacGenerate(
        integJobId,
        CRYPTO_OPERATIONMODE_SINGLECALL,
        context->outPBuf->payload,
        context->outContentLength,
        macFull,
        &macLen);
    if (Std_Return != E_OK)
    {
        return Std_Return;
    }

    IStdLib_MemCpy(context->outPBuf->payload + context->outContentLength, macFull, context->IntegOutputLen);
    context->outContentLength += context->IntegOutputLen;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
/**
 * @brief		Build IKE_AUTH packet.
 * @param[in]	context   : IKE context pointer.
 * @return		Std_ReturnType.
 * @reentrant	TRUE
 * @synchronous TRUE
 * @trace		 -
 */
Std_ReturnType TcpIp_IkeBuildAuthRequest(uint32 IkeConnIdx)
{
    Std_ReturnType  Std_Return = E_NOT_OK;
    IkeConnContext* context    = &IkeConnContextTable[IkeConnIdx];
    uint8 *         writePtr = context->outPBuf->payload, *encryptPtr = NULL;

    IStdLib_MemSet(context->outPBuf->payload, 0, context->outPBuf->len);

    /* initiator SPI */
    IStdLib_MemCpy(writePtr, context->InitiatorSPI, IKE_IKE_SPI_LEN);
    writePtr += IKE_IKE_SPI_LEN;

    /* responder SPI */
    IStdLib_MemCpy(writePtr, context->ResponderSPI, IKE_IKE_SPI_LEN);
    writePtr += IKE_IKE_SPI_LEN;

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_SK;
    writePtr += 1u;

    /* version */
    writePtr[0] = (uint8)IKE_VERSION_2;
    writePtr += 1u;

    /* exchange type */
    writePtr[0] = (uint8)IKE_EXCHANGE_TYPE_AUTH;
    writePtr += 1u;

    /* Flags, Initiator bit set */
    Bfx_SetBit_u8u8(writePtr, IKE_INITIATOR_BIT);
    Bfx_ClrBit_u8u8(writePtr, IKE_VERSION_BIT);
    Bfx_ClrBit_u8u8(writePtr, IKE_RESPONDER_BIT);
    writePtr += 1u;

    /* message id */
    TCPIP_CHG_PARA_ENCODE_32(writePtr, context->MessageId);
    writePtr += 4u;

    /* calculate length later */
    uint8* authLengthPtr = writePtr;
    writePtr += 4u;

    /**************************encrypted payload (SK)*************************/

    /* next payload */
    writePtr[0] = (uint8)IKE_NEXT_PAYLOAD_TYPE_IDI;
    /* critical bit */
    writePtr[1] = 0;
    writePtr += 2u;

    /* calculate length later */
    uint8* skLengthPtr = writePtr;
    writePtr += 2u;

    uint32 IVLen = IKE_IV_LEN;
    Std_Return   = TcpIp_IkeRandomGenerateOnce(context, context->IV, &IVLen);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }
    IStdLib_MemCpy(writePtr, context->IV, IKE_IV_LEN);
    writePtr += IKE_IV_LEN;

    /**************the following data needs encrypted***********/
    encryptPtr = writePtr;
    /* IDi payload */
    Std_Return = TcpIp_Ike_BuildIDiPayload(IkeConnIdx, &writePtr);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* IDr payload */
    TcpIp_Ike_BuildIDrPayload(IkeConnIdx, &writePtr);

    /* Auth payload */
    Std_Return = TcpIp_IkeBuildAuthPayload(context, &writePtr, IkeConnIdx);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* use transport mode */
    TcpIp_IkeBuildNotifyPayload(context, &writePtr, (uint16)IKE_NOTIFY_TYPE_USE_TRANSPORT_MODE);

    /* SA2 payload */
    Std_Return = TcpIp_Ike_BuildSa2Payload(context, &writePtr);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    /* TSi TSr payload */
    TcpIp_IkeBuildTsPayload(context, &writePtr);

    /* encryption */
    uint32 dataLen = writePtr - encryptPtr;
    TcpIp_IkeEncrypt(context, encryptPtr, &dataLen);
    writePtr                  = encryptPtr + dataLen;
    context->outContentLength = writePtr - (uint8*)context->outPBuf->payload;

    /* payload lengths (do not bump outContentLength until ICV is appended) */
    uint32 skPayloadLen      = context->outContentLength - IKE_HEADER_LEN;
    uint32 skPayloadTotalLen = skPayloadLen + context->IntegOutputLen;
    TCPIP_CHG_PARA_ENCODE_16(skLengthPtr, skPayloadTotalLen);

    uint32 msgTotalLen = context->outContentLength + context->IntegOutputLen;
    TCPIP_CHG_PARA_ENCODE_32(authLengthPtr, msgTotalLen);

    /* integrity */
    Std_Return = TcpIp_IkeICVGenerate(context);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeContextInit(uint32 IkeConnIdx)
{
    const IKE_ConnectionType* conn      = &IKE_Config.Connections->Connection[IkeConnIdx];
    IkeConnContext*           context   = &IkeConnContextTable[IkeConnIdx];
    TcpIp_SocketIdType        socketId  = TCPIP_SOCKETID_INVALID;
    uint16                    localPort = IKE_Config.Connections->LocalPort;

    if (E_OK != TcpIp_IKEGetSocket(TCPIP_AF_INET, TCPIP_IPPROTO_UDP, &socketId))
    {
        return E_NOT_OK;
    }

    if (E_OK != TcpIp_Bind(socketId, conn->LocalAddressId, &localPort))
    {
        (void)TcpIp_Close(socketId, TRUE);
        return E_NOT_OK;
    }

    context->SocketId = socketId;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeSendAuth(uint32 IkeConnIdx)
{
    const IKE_ConnectionType* conn    = &IKE_Config.Connections->Connection[IkeConnIdx];
    IkeConnContext*           context = &IkeConnContextTable[IkeConnIdx];

    if (context->RetransmitTries >= IKE_Config.Connections->RetransmitTries)
    {
        return E_NOT_OK;
    }

    Std_ReturnType Std_Return = TcpIp_IkeBuildAuthRequest(IkeConnIdx);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    TcpIp_SockAddrType remoteAddr = {
        .domain  = TCPIP_AF_INET,
        .port    = conn->RemotePort,
        .addr[0] = conn->RemoteAddress,
    };

    TcpIp_UdpTransmit(context->SocketId, context->outPBuf->payload, &remoteAddr, context->outContentLength);

    if (context->RetransmitTries)
    {
        context->RetransmitTimeoutMs *= IKE_Config.Connections->RetransmitBase;
    }

    TcpIp_IkeReloadRetransmitTick(context);
    context->RetransmitTries++;
    context->ConnStatus = IKE_CONN_AUTH_SENT;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeSendSaInit(uint32 IkeConnIdx)
{
    Std_ReturnType            Std_Return = E_OK;
    const IKE_ConnectionType* conn       = &IKE_Config.Connections->Connection[IkeConnIdx];
    IkeConnContext*           context    = &IkeConnContextTable[IkeConnIdx];

    if (context->RetransmitTries >= IKE_Config.Connections->RetransmitTries)
    {
        return E_NOT_OK;
    }

    if (TCPIP_SOCKETID_INVALID == context->SocketId)
    {
        Std_Return = TcpIp_IkeContextInit(IkeConnIdx);
        if (E_OK != Std_Return)
        {
            return Std_Return;
        }
    }

    Std_Return = TcpIp_IkeBuildSaInit(context);
    if (E_OK != Std_Return)
    {
        return Std_Return;
    }

    TcpIp_SockAddrType remoteAddr = {
        .domain  = TCPIP_AF_INET,
        .port    = conn->RemotePort,
        .addr[0] = conn->RemoteAddress,
    };

    TcpIp_UdpTransmit(context->SocketId, context->outPBuf->payload, &remoteAddr, context->outContentLength);

    if (context->RetransmitTries)
    {
        context->RetransmitTimeoutMs *= IKE_Config.Connections->RetransmitBase;
    }

    TcpIp_IkeReloadRetransmitTick(context);
    context->RetransmitTries++;
    context->ConnStatus = IKE_CONN_INIT_SENT;

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeInitTimeout(uint32 IkeConnIdx)
{
    IkeConnContext* context = &IkeConnContextTable[IkeConnIdx];

    if (TcpIp_IkeUpdateRetransmitTickAndCheckTimeout(context))
    {
        TcpIp_IkeSendSaInit(IkeConnIdx);
    }

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
Std_ReturnType TcpIp_IkeAuthTimeout(uint32 IkeConnIdx)
{
    IkeConnContext* context = &IkeConnContextTable[IkeConnIdx];

    if (TcpIp_IkeUpdateRetransmitTickAndCheckTimeout(context))
    {
        TcpIp_IkeSendAuth(IkeConnIdx);
    }

    return E_OK;
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#define TCPIP_START_SEC_CODE
#include "TcpIp_MemMap.h"
void TcpIp_IkeInitHandle(ApplicationType partitionIndex)
{
    IkeConnContext* context = NULL;

    for (uint32 i = 0; i < IKE_CONNECTION_NUMBER; i++)
    {
        const IKE_ConnectionType* conn = &IKE_Config.Connections->Connection[i];
        if (FALSE == conn->Autostart)
        {
            continue;
        }

#if (STD_ON == TCPIP_PARTITION_USED)
        const TcpIp_LocalAddrType* localAddrCfgPtr = &TCPIP_LOCALADDR_CONFIG(conn->LocalAddressId);
        if (localAddrCfgPtr->PartitionIndex != partitionIndex)
        {
            continue;
        }
#else
        TCPIP_UNUSED_ARG(partitionIndex);
#endif

        context = &IkeConnContextTable[i];
        switch (context->ConnStatus)
        {
        case IKE_CONN_CLOSED:
        {
            TcpIp_IkeSendSaInit(i);
            break;
        }

        case IKE_CONN_INIT_SENT:
        {
            TcpIp_IkeInitTimeout(i);
            break;
        }

        case IKE_CONN_INIT_RCVD:
        {
            TcpIp_IkeSendAuth(i);
            break;
        }

        case IKE_CONN_AUTH_SENT:
        {
            TcpIp_IkeAuthTimeout(i);
            break;
        }

        default:
            break;
        }
    }
}
#define TCPIP_STOP_SEC_CODE
#include "TcpIp_MemMap.h"

#endif /* TCPIP_IPSEC_ENABLED */
