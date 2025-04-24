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
**  FILENAME    : Arch_Extend.h                                               **
**                                                                            **
**  Created on  :                                                             **
**  Author      : i-soft-os                                                   **
**  Vendor      :                                                             **
**  DESCRIPTION : Extended functions                                          **
**                                                                            **
**  SPECIFICATION(S) :   AUTOSAR classic Platform r19                         **
**  Version :   V1.0                                                          **
**                                                                            **
*******************************************************************************/
#ifndef Arch_EXTEND_H
#define Arch_EXTEND_H

/*=======[I N C L U D E S]====================================================*/
#include "Os_Types.h"

/*=======[V E R S I O N  C H E C K]===========================================*/

/*=======[M A C R O S]========================================================*/

/*=======[E X T E R N A L   D A T A]==========================================*/

/*=======[F U N C T I O N   D E C L A R A T I O N S]========*/
extern FUNC(void, OS_CODE) Arch_CheckCPUInformation(void);

#endif /* #ifndef Arch_EXTEND_H */
/*=======[E N D   O F   F I L E]==============================================*/
