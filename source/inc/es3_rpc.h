/**************************************************************************
*  Copyright (c) 2021-2023 by Michael Fischer (www.emb4fun.de).
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
**************************************************************************/
#if !defined(__ES3_RPC_H__)
#define __ES3_RPC_H__

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
#define PACKED(_a)    __attribute__((__packed__)) _a
#endif

/**************************************************************************
*  Global Definitions
**************************************************************************/

/*
 * ES3 server port and slot count
 */
#define ES3_SERVER_PORT          54322

/*
 * If the value ES3_SLOT_COUNT will be changed, then a new version of
 * es3slotlist must also be created with the changed value.
 */
#define ES3_SLOT_COUNT           256


/*
 * ES3 error codes
 */
#define ES3_RPC_OK               0
#define ES3_RPC_ERROR            -1
#define ES3_RPC_ERR_LOCKED       -2
#define ES3_RPC_ERR_SLOT         -3
#define ES3_RPC_ERR_USER         -4
#define ES3_RPC_ERR_ECC          -5
#define ES3_RPC_ERR_LEN          -6
#define ES3_RPC_ERR_FUNC         -7

/*
 * ES3 header infos
 */
#define ES3_RPC_HEADER_MAGIC_1   0x52335345  // "ES3RPC"
#define ES3_RPC_HEADER_MAGIC_2   0x00004350
#define ES3_RPC_SIZEVER          ((((uint32_t)sizeof(es3_header_t)) << 16) | ES3_RPC_VERSION)
#define ES3_RPC_HEADER_SIZE      sizeof(es3_header_t)

#define ES3_RPC_VERSION          1

#define ES3_RPC_USER_SIZE        64
#define ES3_RPC_SIG_SIZE         87
#define ES3_RPC_SLOT_SIZE        20
#define ES3_RPC_PUB_SIZE         512


/*
 * RPC data structure
 */

/*************************************************************************/

/*
 * Sign
 */
typedef struct
{
   char     Slot[ES3_RPC_SLOT_SIZE];   /* Key name like firefly */
   uint8_t  Hash[32];
} PACKED(es3_call_sign_t);
#define ES3_CALL_SIGN_SIZE             sizeof(es3_call_sign_t)

typedef struct
{
   char     Slot[ES3_RPC_SLOT_SIZE];   /* Key name like firefly */
   uint8_t  SigLen;
   uint8_t  Sig[ES3_RPC_SIG_SIZE];
} PACKED(es3_reply_sign_t);
#define ES3_REPLY_SIGN_SIZE            sizeof(es3_reply_sign_t)


/*-----------------------------------------------------------------------*/

/*
 * GetPub
 */
typedef struct
{
   char     Slot[ES3_RPC_SLOT_SIZE];
} PACKED(es3_call_get_pub_t);
#define ES3_CALL_GET_PUB_SIZE          sizeof(es3_call_get_pub_t)


typedef struct
{
   char     Pub[ES3_RPC_PUB_SIZE];
} PACKED(es3_reply_get_pub_t);
#define ES3_REPLY_GET_PUB_SIZE         sizeof(es3_reply_get_pub_t)


/*-----------------------------------------------------------------------*/

/*
 * GetList
 */
typedef struct
{
   char     Slot[ES3_RPC_SLOT_SIZE];
} PACKED(es3_call_get_lis_t);
#define ES3_CALL_GET_LIST_SIZE         sizeof(es3_call_get_lis_t)


typedef struct
{
   char     SlotArray[ES3_SLOT_COUNT][ES3_RPC_SLOT_SIZE];
} PACKED(es3_reply_get_list_t);
#define ES3_REPLY_GET_LIST_SIZE        sizeof(es3_reply_get_list_t)


/*************************************************************************/

typedef union
{
   es3_call_sign_t         cSign;
   es3_reply_sign_t        rSign;

   es3_call_get_pub_t      cGetPub;
   es3_reply_get_pub_t     rGetPub;

   es3_call_get_lis_t      cGetList;
   es3_reply_get_list_t    rGetList;

} PACKED(es3_data_t);

/*************************************************************************/

/*
 * RPC functions
 */

typedef enum
{
   ES3_MSG_SIGN = 0,
   ES3_MSG_GET_PUB,
   ES3_MSG_GET_LIST,

   /**************************/
   ES3_MSG_END = 0xFFFFFFFF
} es3_msg_func;

/*************************************************************************/

typedef struct _es3_header_
{
   uint32_t     Magic1;
   uint32_t     Magic2;
   uint32_t     SizeVer;
   es3_msg_func Func;
   uint32_t     XID;
   char         User[ES3_RPC_USER_SIZE];
   char         SigLen;
   uint8_t      Sig[ES3_RPC_SIG_SIZE];
   uint32_t     Len;
   int32_t      Result;
} PACKED(es3_header_t);

typedef struct _es3_msg_
{
   es3_header_t   Header;
   es3_data_t     Data;
} PACKED(es3_msg_t);


#ifdef _WINDOWS
#pragma pack()
#endif

/**************************************************************************
*  Macro Definitions
**************************************************************************/

/**************************************************************************
*  Functions Definitions
**************************************************************************/

#endif /* !__ES3_RPC_H__ */

/*** EOF ***/
