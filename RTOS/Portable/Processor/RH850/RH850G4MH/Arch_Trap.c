/*******************************************************************************
**                                                                            **
** Copyright (C) iSOFT   (2016-2023)                                          **
**                                                                            **
** All rights reserved.                                                       **
**                                                                            **
** This document contains proprietary information belonging to iSOFT.         **
** Passing on and copying of this document, and communication                 **
** of its contents is not permitted without prior written authorization.      **
**                                                                            **
********************************************************************************
**                                                                            **
**  FILENAME    : Arch_Trap.c                                                 **
**                                                                            **
**  Created on  :                                                             **
**  Author      : i-soft-os                                                   **
**  Vendor      :                                                             **
**  DESCRIPTION : Trap manager                                                **
**                                                                            **
**  SPECIFICATION(S) :   AUTOSAR classic Platform r19                         **
**  Version :   V1.0                                                          **
**                                                                            **
*******************************************************************************/

/*=======[I N C L U D E S]====================================================*/
#include "Os_Internal.h"

/*=======[F U N C T I O N   I M P L E M E N T A T I O N S]====================*/
FUNC(void, OS_CODE) Os_MipMdp(void)
{
    uint32 MPU_RWX_ERR = (OS_ARCH_REG_READ(OS_FEIC_NUM) >> 4U) & 0x09U;

#if ((OS_SC2 == CFG_SC) || (OS_SC3 == CFG_SC) || (OS_SC4 == CFG_SC))
#if (TRUE == CFG_PROTECTIONHOOK)
    uint32 WhoHook = OS_TMPROT_HOOK_OSAPP;

    if (OS_LEVEL_TASK == Os_SCB.sysOsLevel)
    {
        WhoHook = OS_TMPROT_HOOK_TASK;
    }
    else if (OS_LEVEL_ISR2 == Os_SCB.sysOsLevel)
    {
        WhoHook = OS_TMPROT_HOOK_ISR;
    }
    else
    {
        /* Do nothing. */
    }
#endif /* TRUE == CFG_PROTECTIONHOOK */
#endif /* (OS_SC2 == CFG_SC) || (OS_SC3 == CFG_SC) || (OS_SC4 == CFG_SC)*/

#if ((OS_SC2 == CFG_SC) || (OS_SC3 == CFG_SC) || (OS_SC4 == CFG_SC))
#if (TRUE == CFG_ERRORHOOK)
    (void)ErrorHook(E_OS_PROTECTION_MEMORY);
#endif /* TRUE == CFG_ERRORHOOK */

#if (TRUE == CFG_PROTECTIONHOOK)
    /* OS044: Memory protection hook. */
    (void)Os_CallProtectionHook(E_OS_PROTECTION_MEMORY, WhoHook);
#endif /* TRUE == CFG_PROTECTIONHOOK */
#else
#if (TRUE == CFG_ERRORHOOK)
    (void)ErrorHook(E_OS_PROTECTION_EXCEPTION);
#endif /* TRUE == CFG_ERRORHOOK */
#endif /* (OS_SC2 == CFG_SC) || (OS_SC3 == CFG_SC) || (OS_SC4 == CFG_SC) */

    while (0U != MPU_RWX_ERR)
    {
        /* Nothing to do. */
    }
}

FUNC(void, OS_CODE) Os_FENMI(void)
{
    while (1)
    {
        /* Nothing to do. */
    }
}

FUNC(void, OS_CODE) Os_FEIntHandler(void)
{
    /* Just ignore this interrupt.  */
    while (1)
    {
        /* Nothing to do. */
    }
}

/*=======[E N D   O F   F I L E]==============================================*/
