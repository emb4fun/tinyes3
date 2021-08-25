/**************************************************************************
*  Copyright (c) 2021 by Michael Fischer (www.emb4fun.de).
*  All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without 
*  modification, are permitted provided that the following conditions 
*  are met:
*  
*  1. Redistributions of source code must retain the above copyright 
*     notice, this list of conditions and the following disclaimer.
*
*  2. Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the 
*     documentation and/or other materials provided with the distribution.
*
*  3. Neither the name of the author nor the names of its contributors may 
*     be used to endorse or promote products derived from this software 
*     without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
*  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
*  THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
*  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
*  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
*  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
*  AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
*  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
*  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
*  SUCH DAMAGE.
*
***************************************************************************
*  History:
*
*  14.04.2021  mifi  First Version.
*  08.05.2021  mifi  Reduce ES3_SIGN_HEAD size.
**************************************************************************/
#if !defined(__ES3_SIGN_H__)
#define __ES3_SIGN_H__

/**************************************************************************
*  Includes
**************************************************************************/

#ifdef _MSC_VER
#include <windows.h>
#include "stdint.h"
#else
#include <stdint.h>
#endif

#ifdef _WINDOWS
#pragma pack(1)
#define PACKED(_a)   _a
#endif

#if !defined(PACKED)
#define PACKED(_a)   __attribute__((__packed__)) _a
#endif   

/**************************************************************************
*  Global Definitions
**************************************************************************/

/*
 * Signing Header
 */
 
#define ES3_HEAD_MAGIC1    0x594E4954  // "TINYES3"
#define ES3_HEAD_MAGIC2    0x00335345
#define ES3_HEAD_SIZEVER   ((((uint32_t)sizeof(ES3_SIGN_HEAD)) << 16) | 0x0001)
#define ES3_HEAD_SLOT_SIZE 20
#define ES3_HEAD_SIG_SIZE  87

typedef struct _es3_sign_head_
{
   uint32_t dMagic1;
   uint32_t dMagic2;
   uint32_t dSizeVersion;
   uint32_t dDataSize;
   char      Slot[ES3_HEAD_SLOT_SIZE]; /* Key name like firefly */
   uint8_t  bSigLen;
   uint8_t   Signature[ES3_HEAD_SIG_SIZE];
   uint32_t dCRC32;
} PACKED(ES3_SIGN_HEAD);


#ifdef _WINDOWS
#pragma pack()
#endif

/**************************************************************************
*  Macro Definitions
**************************************************************************/

/**************************************************************************
*  Functions Definitions
**************************************************************************/

#endif /* !__ES3_SIGN_H__ */

/*** EOF ***/
