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
#define __ES3_C__

/*=======================================================================*/
/*  Includes                                                             */
/*=======================================================================*/

#include <string.h>
#include <stdlib.h>
#include "tal.h"
#include "tcts.h"
#include "ipweb.h"
#include "fsapi.h"
#include "ff.h"
#include "es3.h"
#include "es3_sign.h"
#include "es3_rpc.h"
#include "terminal.h"
#include "ipstack.h"
#include "adler32.h"

#include "mbedtls/platform.h"
#include "mbedtls/base64.h"
#include "mbedtls/md5.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"

/*lint -save -e801*/

/*=======================================================================*/
/*  Extern                                                               */
/*=======================================================================*/

/*=======================================================================*/
/*  All Structures and Common Constants                                  */
/*=======================================================================*/

#define MAX_SLOT_CNT    ES3_SLOT_COUNT
#define MAX_USER_CNT    16


/*
 * Some external swithes are not ready to use if the link
 * is available. Therefore wait a short time.
 */
#define DELAY_AFTER_LINK_MS   2000

/*
 * End macro
 */
#define GOTO_END(_a)  { rc = _a; goto end; }

/*
 * Policy mask
 */
#define SIZE_OK         0x01
#define UPPERCASE_OK    0x02
#define LOWERCASE_OK    0x04
#define NUMBER_OK       0x08
#define SYMBOL_OK       0x10

/*
 * Status infos
 */
#define STATUS_MUST_INIT         -1
#define STATUS_UNLOCKED          0
#define STATUS_LOCKED            1

/*
 * Error infos
 */
//#define ES3_OK                   0
//#define ES3_ERROR                -1
#define ES3_ERR_NO_INIT          -2
#define ES3_ERR_PASS_POLICY      -3

#define ES3_ERR_NO_LOCKED        -4
#define ES3_ERR_PASS_WRONG       -5
#define ES3_ERR_NO_UNLOCK        -6
#define ES3_ERR_KEY_POLICY       -7
#define ES3_ERR_RESOURCES        -8
#define ES3_ERR_KEY_DUPLICAT     -9
#define ES3_ERR_NOT_AVAILABLE    -10
#define ES3_ERR_USER_DUPLICAT    -11


#define ES3_ERR_EKS_PATH         -100
#define ES3_ERR_PKCS5            -101
#define ES3_ERR_AES              -102
#define ES3_ERR_EKS_KEY_WRITE    -103

#define ES3_ERR_SLOT             -200
#define ES3_ERR_SLOT_DRBG_SEED   -201
#define ES3_ERR_SLOT_PK_SETUP    -202
#define ES3_ERR_SLOT_GEN_KEY     -203
#define ES3_ERR_SLOT_KEY_PEM     -204
#define ES3_ERR_SLOT_PUBKEY_PEM  -205
#define ES3_ERR_SLOT_ENCRYPT     -206
#define ES3_ERR_SLOT_DECRYPT     -207
#define ES3_ERR_SLOT_DATA        -208
#define ES3_ERR_SLOT_WRITE       -209

#define ES3_ERR_USER             -300
#define ES3_ERR_USER_DECODE      -301
#define ES3_ERR_USER_ENCRYPT     -302
#define ES3_ERR_USER_DECRYPT     -303
#define ES3_ERR_USER_DATA        -304
#define ES3_ERR_USER_WRITE       -305
#define ES3_ERR_USER_DELETE      -306

/*
 * EKS keylen, will be used for AES too
 */
#define EKS_KEY_LEN        32
#define AES_IV_BYTES_CNT   16
#define AES_DATA_BYTES_CNT 16

/*
 * Slot
 */
#define SLOT_RANDOM_SIZE   AES_IV_BYTES_CNT
#define SLOT_MAGIC1        0x53335345  // "ES3SLOT"
#define SLOT_MAGIC2        0x00544F4C 
#define SLOT_SIZEVER       ((((uint32_t)sizeof(ES3_SLOT)) << 16) | 0x0001)
#define SLOT_NAME_SIZE     20
#define SLOT_BUFFER_SIZE   512 

#define SLOT_FLAG_ENABLE   0x0001

typedef struct __attribute__((__packed__)) _es3_slot_
{
   uint8_t   Random[SLOT_RANDOM_SIZE];
   uint32_t dMagic1;
   uint32_t dMagic2;
   uint32_t dSizeVersion;
   uint32_t dFlags;
   uint32_t dID;
   uint32_t  Dummy[2];
   char      Name[SLOT_NAME_SIZE];
   uint8_t   Priv[SLOT_BUFFER_SIZE];
   uint8_t   Pub[SLOT_BUFFER_SIZE];
} ES3_SLOT;

#define SLOT_MAX_CNT       MAX_SLOT_CNT
#define ROOT_OF_TRUST      "root-of-trust"
#define KEY_NAME_MAX       16

/*
 * User
 */
#define USER_RANDOM_SIZE   AES_IV_BYTES_CNT
#define USER_MAGIC1        0x55335345  // "ES3USER"
#define USER_MAGIC2        0x00524553
#define USER_SIZEVER       ((((uint32_t)sizeof(ES3_USER)) << 16) | 0x0001)
#define USER_NAME_SIZE     64

typedef struct __attribute__((__packed__)) _es3_user_
{
   uint8_t   Random[USER_RANDOM_SIZE];
   uint32_t dMagic1;
   uint32_t dMagic2;
   uint32_t dSizeVersion;
   uint32_t dFlags; 
   char      User[USER_NAME_SIZE];
   char      PubKey[256];
   uint16_t wPubKeyRawLen;
   uint8_t   PubKeyRaw[256];
   uint8_t   Hash[16];   
   uint8_t   Dummy[14];
} ES3_USER;

#define USER_MAX_CNT       MAX_USER_CNT

/*=======================================================================*/
/*  Definition of all global Data                                        */
/*=======================================================================*/

/*=======================================================================*/
/*  Definition of all local Data                                         */
/*=======================================================================*/

/* 
 * Some TASK variables like stack and task control block.
 */
static OS_STACK (ES3Stack, TASK_IP_ES3_STK_SIZE);
static OS_TCB TCBES3;

static OS_SEMA Sema;

static uint8_t EKSKey[EKS_KEY_LEN];
static uint8_t EKSSalt[] = "TinyEKS";
static uint8_t EKSTest[] = "TinyEKS"; /* Must have a size of less or equal to 15 chars */
static int    nEKSStatus = STATUS_MUST_INIT;

static ES3_SLOT SlotArray[SLOT_MAX_CNT];
static ES3_USER UserArray[USER_MAX_CNT];

/*=======================================================================*/
/*  Definition of all local Procedures                                   */
/*=======================================================================*/

/*************************************************************************/
/*  UserIsAvailable                                                      */
/*                                                                       */
/*  In    : pUser                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int UserIsAvailable (ES3_USER *pUser)
{
   int rc = ES3_OK;
   int Index;
   
   for (Index = 0; Index < USER_MAX_CNT; Index++)
   {
      /* Check if index is used */
      if ((USER_MAGIC1 == UserArray[Index].dMagic1) &&
          (USER_MAGIC2 == UserArray[Index].dMagic2))
      {
         /* Check if user is available */
         if (0 == strcmp(UserArray[Index].User, pUser->User))
         {
            rc = ES3_ERROR;
            break;
         }
      }
   }
   
   return(rc);
} /* UserIsAvailable */

/*************************************************************************/
/*  UserDecode                                                           */
/*                                                                       */
/*  In    : pUser, pData                                                 */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int UserDecode (ES3_USER *pUser, char *pData)
{
   int                rc = ES3_ERR_USER;
   mbedtls_pk_context ctx;
   size_t             len;
   static char        Temp[256];  
   char             *pPtr;
   char             *pStart;
   char             *pEnd;
   uint8_t          *buf = NULL;
   uint8_t          *p;

   mbedtls_pk_init(&ctx);

   /* Copy key */   
   snprintf(Temp, sizeof(Temp), "%s", pData);

   /* Check type */
   pStart = strstr(Temp, "es3-nistp256");
   if (pStart != NULL)
   {
      /* Only NIST P-256 is supported now */
      pStart += 12;
   }
   else
   {  
      GOTO_END(ES3_ERR_USER); /*lint !e527*/
   }   
   
   /* Jump over spaces */
   while (0x20 == *pStart)
   {
      pStart++;
   }
   
   /* Find end of data */
   pEnd = strstr(pStart, " ");
   if (pEnd != NULL)
   {
      *pEnd = 0;
   }
   else
   {  
      GOTO_END(ES3_ERR_USER); /*lint !e527*/
   }   
   
   /* Save public key */   
   snprintf(pUser->PubKey, sizeof(pUser->PubKey), "%s", pStart);
    
   /* Convert '-' to 0x0A */
   pPtr = pStart;
   while (*pPtr != 0)
   {
      if ('-' == *pPtr)
      {
         *pPtr = 0x0A;
      }
      pPtr++;
   }

   /* Dummy decode to get size of decode buffer */
   rc = mbedtls_base64_decode(NULL, 0, &len, (uint8_t*)pStart, strlen(pStart));   
   if (rc == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) GOTO_END(ES3_ERR_USER);

   /* Allocate decode buffer */   
   buf = mbedtls_calloc(1, len);
   if (NULL == buf) GOTO_END(ES3_ERR_USER);

   /* Decode now */
   rc = mbedtls_base64_decode(buf, len, &len, (uint8_t*)pStart, strlen(pStart));
   if (rc != 0) GOTO_END(ES3_ERR_USER);
   
   /* 
    * At this point buf with len contains the raw key data.
    */

   /* Save prublic key raw data */
   if (len < sizeof(pUser->PubKeyRaw))
   {
      pUser->wPubKeyRawLen = (uint16_t)len;
      memcpy(pUser->PubKeyRaw, buf, len);
   }
    
   /* Create MD5 hash of decoded data */    
   rc = mbedtls_md5(buf, len, pUser->Hash);
   if (rc != 0) GOTO_END(ES3_ERR_USER);

   /* Check if this is a valid key */
   p = buf;
   rc = mbedtls_pk_parse_subpubkey(&p,  p + len, &ctx);
   if (rc != 0) GOTO_END(ES3_ERR_USER);
   
   /* 
    * At this point we have a valid ECC key.
    */
    
   /* Find user and computer name */
   if ((pEnd != NULL) && (pEnd < (pData + strlen(pData))))  /*lint !e774*/    
   {
      /* Jump to the name@cumputer */
      pEnd++;
      
      /* Jump over spaces */
      while (0x20 == *pEnd)
      {
         pEnd++;
      }
      
      /* This must be the user and computer name */
      
      /* Remove spaces at the end if available */         
      pPtr = strstr(pEnd, " ");
      if (pPtr != NULL)
      {
         *pPtr = 0;
      }
      
      /* Copy user and computer name without spaces */
      snprintf(pUser->User, sizeof(pUser->User), "%s", pEnd);
   }
   else
   {
      /* Error */
      rc = ES3_ERR_USER;
   }

   
end:

   /* Free buffer if available */
   if (buf != NULL)
   {
      mbedtls_free(buf);
   }

   /* Clear data */
   memset(Temp, 0x00, sizeof(Temp));

   /* Free the mbedTLS content */
   mbedtls_pk_free(&ctx);

   return(rc);
} /* UserDecode */    

/*************************************************************************/
/*  UserEncrypt                                                          */
/*                                                                       */
/*  In    : pUser                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int UserEncrypt (ES3_USER *pUser)
{
   int                        rc;
   static mbedtls_aes_context ctx;
   static uint8_t             Random[USER_RANDOM_SIZE];
   
   memcpy(Random, pUser->Random, USER_RANDOM_SIZE);

   /* Encrypt data */
   mbedtls_aes_init(&ctx);
   mbedtls_aes_setkey_enc(&ctx, EKSKey, (EKS_KEY_LEN*8));
   rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 
                              sizeof(ES3_USER) - USER_RANDOM_SIZE, 
                              pUser->Random, 
                              (uint8_t*)&pUser->dMagic1,
                              (uint8_t*)&pUser->dMagic1);
   mbedtls_aes_free(&ctx);

   /* Check for AES error */
   if (rc != 0) GOTO_END(ES3_ERR_USER_ENCRYPT);
   memcpy(pUser->Random, Random, USER_RANDOM_SIZE);
   
   rc = ES3_OK;

end:
   return(rc);
} /* UserEncrypt */

/*************************************************************************/
/*  UserDecrypt                                                          */
/*                                                                       */
/*  In    : pUser                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int UserDecrypt (ES3_USER *pUser)
{
   int                        rc;
   static mbedtls_aes_context ctx;
   static uint8_t             Random[USER_RANDOM_SIZE];
   
   memcpy(Random, pUser->Random, USER_RANDOM_SIZE);

   /* Decrypt data */
   mbedtls_aes_init(&ctx);
   mbedtls_aes_setkey_dec(&ctx, EKSKey, (EKS_KEY_LEN*8));
   rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 
                              sizeof(ES3_USER) - USER_RANDOM_SIZE, 
                              pUser->Random, 
                              (uint8_t*)&pUser->dMagic1,
                              (uint8_t*)&pUser->dMagic1);
   mbedtls_aes_free(&ctx);

   /* Check for AES error */
   if (rc != 0) GOTO_END(ES3_ERR_USER_DECRYPT);
   memcpy(pUser->Random, Random, USER_RANDOM_SIZE);

   /* Some user checks */
   if ((USER_MAGIC1  == pUser->dMagic1)     && 
       (USER_MAGIC2  == pUser->dMagic2)     &&     
       (USER_SIZEVER == pUser->dSizeVersion))
   {
      rc = ES3_OK;
   }
   else
   {
      /* Wrong data */
      rc = ES3_ERR_USER_DATA;
   }

end:
   return(rc);
} /* UserDecrypt */

/*************************************************************************/
/*  UserDel                                                              */
/*                                                                       */
/*  In    : bIndex, pData                                                */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int UserDel (uint8_t bIndex, ES3_USER *pUser)
{
   int      rc = ES3_ERR_USER;
   FRESULT  res;
   char     UserName[24];

   /* Check valid user index */
   if (bIndex >= USER_MAX_CNT) GOTO_END(ES3_ERR_USER); 

   /* Delete user data */
   memset(pUser, 0x00, sizeof(ES3_USER));
   
   snprintf(UserName, sizeof(UserName), "/eks/user%02d.key", bIndex);
   res = f_unlink(UserName);
   if (res != FR_OK) GOTO_END(ES3_ERR_USER_DELETE);
   
   rc = 0;

end:

   return(rc);
} /* UserDel */

/*************************************************************************/
/*  UserAdd                                                              */
/*                                                                       */
/*  In    : bIndex, pData                                                */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int UserAdd (uint8_t bIndex, char *pData)
{
   int               rc = ES3_ERR_USER;
   int               fd;
   static ES3_USER   TempUser;
   ES3_USER        *pUser = NULL;
   char              UserName[24];

   /* Check valid user index */
   if (bIndex >= USER_MAX_CNT) GOTO_END(ES3_ERR_USER); 
   pUser = &UserArray[bIndex];
   
   /* Check if the user is not in used */
   if ((USER_MAGIC1 == pUser->dMagic1) && (USER_MAGIC2 == pUser->dMagic2)) GOTO_END(ES3_ERR_USER); 

   /* Prepare user content */
   memset(&TempUser, 0x00, sizeof(ES3_USER));
   tal_CPURngHardwarePoll(TempUser.Random, USER_RANDOM_SIZE);
   TempUser.dMagic1      = USER_MAGIC1;
   TempUser.dMagic2      = USER_MAGIC2;
   TempUser.dSizeVersion = USER_SIZEVER;
   TempUser.dFlags       = 0;    /* Prevent lint warning */
   TempUser.Dummy[0]     = 0;    /* Prevent lint warning */
   
   /* User decode */
   rc = UserDecode(&TempUser, pData);
   if (rc != 0) GOTO_END(ES3_ERR_USER_DECODE);
   
   /* Check if user is still available */      
   rc = UserIsAvailable(&TempUser);
   if (rc != 0) GOTO_END(ES3_ERR_USER_DUPLICAT);

   /* Copy temp user to the real user */   
   memcpy(pUser, &TempUser, sizeof(ES3_USER));
   
   /*  Encrypt user */
   rc = UserEncrypt(pUser);  
   if (rc != 0) GOTO_END(ES3_ERR_USER_ENCRYPT);
   
   /* Write encrypted user data */
   snprintf(UserName, sizeof(UserName), "SD0:/eks/user%02d.key", bIndex);
   fd = _open(UserName, _O_BINARY | _O_WRONLY | _O_CREATE_ALWAYS);
   if (-1 == fd) GOTO_END(ES3_ERR_USER_WRITE);
   
   rc = _write(fd, pUser, sizeof(ES3_USER));
   _close(fd);
   if (rc != (int)sizeof(ES3_USER)) GOTO_END(ES3_ERR_USER_WRITE);

   /* Decrypt data */
   rc = UserDecrypt(pUser);

end:

   /* Clear user data in case of an error */
   if ((rc != ES3_OK) && (pUser != NULL))
   {
      memset(pUser, 0x00, sizeof(ES3_USER));
      memset(&TempUser, 0x00, sizeof(ES3_USER));
   }
   
   return(rc);
} /* UserAdd */

/*************************************************************************/
/*  UserUnlock                                                           */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int UserUnlock (void)
{
   int        rc = ES3_ERROR;
   int        fd;
   ES3_USER *pUser = NULL;
   BYTE      bIndex;
   char       UserName[24];
   
   /* Read and decrypt the complete user data */
   
   /* Clear user array first */
   memset(UserArray, 0x00, sizeof(UserArray));
   for(bIndex = 0; bIndex < USER_MAX_CNT; bIndex++)
   {
      pUser = &UserArray[bIndex];
      
      snprintf(UserName, sizeof(UserName), "SD0:/eks/user%02d.key", bIndex);
      fd = _open(UserName, _O_BINARY | _O_RDONLY);
      if (fd != -1)
      {
         rc = _read(fd, pUser, sizeof(ES3_USER));
         _close(fd);
         if (rc != (int)sizeof(ES3_USER))
         {
            /* Error, no user data */
            memset(pUser, 0x00, sizeof(ES3_USER));
         }
         else
         {
            rc = UserDecrypt(pUser);
            if (rc != ES3_OK)
            {
               /* Error, no user data */
               memset(pUser, 0x00, sizeof(ES3_USER));
            }
         }
      } /* end open file */
   } /* end for(bIndex = 0; bIndex < USER_MAX_CNT; bIndex++) */
   
   return(rc);
} /* UserUnlock */

/*************************************************************************/
/*  SlotEncrypt                                                          */
/*                                                                       */
/*  In    : pSlot                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int SlotEncrypt (ES3_SLOT *pSlot)
{
   int                        rc;
   static mbedtls_aes_context ctx;
   static uint8_t             Random[SLOT_RANDOM_SIZE];
   
   memcpy(Random, pSlot->Random, SLOT_RANDOM_SIZE);

   /* Encrypt data */
   mbedtls_aes_init(&ctx);
   mbedtls_aes_setkey_enc(&ctx, EKSKey, (EKS_KEY_LEN*8));
   rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 
                              sizeof(ES3_SLOT) - SLOT_RANDOM_SIZE, 
                              pSlot->Random, 
                              (uint8_t*)&pSlot->dMagic1,
                              (uint8_t*)&pSlot->dMagic1);
   mbedtls_aes_free(&ctx);

   /* Check for AES error */
   if (rc != 0) GOTO_END(ES3_ERR_SLOT_ENCRYPT);
   memcpy(pSlot->Random, Random, SLOT_RANDOM_SIZE);
   
   rc = ES3_OK;

end:
   return(rc);
} /* SlotEncrypt */

/*************************************************************************/
/*  SlotDecrypt                                                          */
/*                                                                       */
/*  In    : pSlot                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int SlotDecrypt (ES3_SLOT *pSlot)
{
   int                        rc;
   static mbedtls_aes_context ctx;
   static uint8_t             Random[SLOT_RANDOM_SIZE];
   
   memcpy(Random, pSlot->Random, SLOT_RANDOM_SIZE);

   /* Decrypt data */
   mbedtls_aes_init(&ctx);
   mbedtls_aes_setkey_dec(&ctx, EKSKey, (EKS_KEY_LEN*8));
   rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 
                              sizeof(ES3_SLOT) - SLOT_RANDOM_SIZE, 
                              pSlot->Random, 
                              (uint8_t*)&pSlot->dMagic1,
                              (uint8_t*)&pSlot->dMagic1);
   mbedtls_aes_free(&ctx);

   /* Check for AES error */
   if (rc != 0) GOTO_END(ES3_ERR_SLOT_ENCRYPT);
   memcpy(pSlot->Random, Random, SLOT_RANDOM_SIZE);

   /* Some slot checks */
   if ((SLOT_MAGIC1  == pSlot->dMagic1)     && 
       (SLOT_MAGIC2  == pSlot->dMagic2)     &&     
       (SLOT_SIZEVER == pSlot->dSizeVersion))
   {
      rc = ES3_OK;
   }
   else
   {
      /* Wrong data */
      rc = ES3_ERR_SLOT_DATA;
   }

end:
   return(rc);
} /* SlotDecrypt */

/*************************************************************************/
/*  SlotUpdate                                                           */
/*                                                                       */
/*  In    : wSlot                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int SlotUpdate (uint16_t wSlot)
{
   int               rc = ES3_ERR_SLOT;
   int               fd;
   ES3_SLOT        *pSlot;
   static ES3_SLOT   Dummy;
   char              SlotName[24];

   /* Check valid range only 1 to SLOT_MAX_CNT-1, 0 is RoT */
   if ((0 == wSlot) || (wSlot >= SLOT_MAX_CNT)) GOTO_END(ES3_ERR_SLOT);

   /* Copy slot data */   
   pSlot = &SlotArray[wSlot];
   memcpy(&Dummy, pSlot, sizeof(ES3_SLOT));

   /*  Enrypt slot */
   rc = SlotEncrypt(&Dummy);  
   if (rc != ES3_OK) GOTO_END(ES3_ERR_SLOT_ENCRYPT);
   
   /* Write encrypted slot data */
   snprintf(SlotName, sizeof(SlotName), "SD0:/eks/slot%03d.key", wSlot);
   fd = _open(SlotName, _O_BINARY | _O_WRONLY | _O_CREATE_ALWAYS);
   if (-1 == fd) GOTO_END(ES3_ERR_SLOT_WRITE);
   
   rc = _write(fd, &Dummy, sizeof(ES3_SLOT));
   _close(fd);
   if (rc != (int)sizeof(ES3_SLOT)) GOTO_END(ES3_ERR_SLOT_WRITE);

   /* Decrypt data */
   rc = SlotDecrypt(&Dummy);
   if (rc != ES3_OK) GOTO_END(ES3_ERR_SLOT_DECRYPT);
   
   /* Compare data */
   if (memcmp(&Dummy, pSlot, sizeof(ES3_SLOT)) != 0) GOTO_END(ES3_ERR_SLOT);
   
   rc = ES3_OK;

end:

   return(rc);
} /* SlotUpdate */

/*************************************************************************/
/*  SlotCreate                                                           */
/*                                                                       */
/*  In    : wSlot, pName                                                 */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int SlotCreate (uint16_t wSlot, char *pName)
{
   int                             rc = ES3_ERR_SLOT;
   int                             res;
   int                             fd;
   static mbedtls_pk_context       pk;
   static mbedtls_entropy_context  entropy;
   static mbedtls_ctr_drbg_context ctr_drbg;
   const char                     *pers = "salt";
   mbedtls_ecp_group_id            grp_id = MBEDTLS_ECP_DP_SECP256R1;
   ES3_SLOT                      *pSlot = NULL;
   char                            SlotName[24];

   /* Prepare key generation */
   mbedtls_pk_init(&pk);
   mbedtls_ctr_drbg_init(&ctr_drbg);
   mbedtls_entropy_init(&entropy);
   
   /* Check valid slot index */
   if (wSlot >= SLOT_MAX_CNT) GOTO_END(ES3_ERR_SLOT); 
   pSlot = &SlotArray[wSlot];
   
   /* Prepare slot content */
   memset(pSlot, 0x00, sizeof(ES3_SLOT));
   tal_CPURngHardwarePoll(pSlot->Random, SLOT_RANDOM_SIZE);
   pSlot->dMagic1      = SLOT_MAGIC1;
   pSlot->dMagic2      = SLOT_MAGIC2;
   pSlot->dSizeVersion = SLOT_SIZEVER;
   pSlot->dFlags       = SLOT_FLAG_ENABLE;
   pSlot->dID          = (uint16_t)grp_id;
   snprintf(pSlot->Name, SLOT_NAME_SIZE, "%s", pName);  
   pSlot->Dummy[0]     = 0;   /* Prevent lint warning */

   /* Seed the random generator */
   res =  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
   if (res != 0) GOTO_END(ES3_ERR_SLOT_DRBG_SEED); 

   /* Generate the key */
   res = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
   if (res != 0) GOTO_END(ES3_ERR_SLOT_PK_SETUP);

   res = mbedtls_ecp_gen_key(grp_id, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, &ctr_drbg);
   if (res != 0) GOTO_END(ES3_ERR_SLOT_GEN_KEY);

   /* "Print" private key */
   res = mbedtls_pk_write_key_pem(&pk, pSlot->Priv, SLOT_BUFFER_SIZE);
   if (res != 0) GOTO_END(ES3_ERR_SLOT_KEY_PEM);
   
   /* "Print" public key */
   res = mbedtls_pk_write_pubkey_pem(&pk, pSlot->Pub, SLOT_BUFFER_SIZE);
   if (res != 0) GOTO_END(ES3_ERR_SLOT_PUBKEY_PEM);
   
   /*  Encrypt slot */
   rc = SlotEncrypt(pSlot);  
   if (rc != 0) GOTO_END(ES3_ERR_SLOT_ENCRYPT);

   /* Write encrypted slot data */
   snprintf(SlotName, sizeof(SlotName), "SD0:/eks/slot%03d.key", wSlot);
   fd = _open(SlotName, _O_BINARY | _O_WRONLY | _O_CREATE_ALWAYS);
   if (-1 == fd) GOTO_END(ES3_ERR_SLOT_WRITE);
   
   rc = _write(fd, pSlot, sizeof(ES3_SLOT));
   _close(fd);
   if (rc != (int)sizeof(ES3_SLOT)) GOTO_END(ES3_ERR_SLOT_WRITE);

   /* Decrypt data */
   rc = SlotDecrypt(pSlot);

end:

   /* Clear slot data in case of an error */
   if ((rc != ES3_OK) && (pSlot != NULL))
   {
      memset(pSlot, 0x00, sizeof(ES3_SLOT));
   }
   
   mbedtls_pk_free(&pk);
   mbedtls_ctr_drbg_free(&ctr_drbg);
   mbedtls_entropy_free(&entropy);
   
   return(rc);
} /* SlotCreate */

/*************************************************************************/
/*  EKSCreateKey                                                         */
/*                                                                       */
/*  In    : pPass, PassLen                                               */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int EKSCreateKey (char *pPass, size_t PassLen)
{
   int rc = ES3_ERROR;
   int ret;

   ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, 
                                       (uint8_t*)pPass, PassLen, 
                                       EKSSalt, sizeof(EKSSalt),
                                       4096,
                                       sizeof(EKSKey), EKSKey);
   if (0 == ret)
   {
      rc = ES3_OK;
   }                                    

   return(rc);
} /* EKSCreateKey */

/*************************************************************************/
/*  EKSUnlock                                                            */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int EKSUnlock (void)
{
   int        rc = ES3_ERROR;
   int        fd;
   ES3_SLOT *pSlot = NULL;
   uint16_t  wSlot;
   char       SlotName[24];
   
   /* Read and decrypt the complete slot data */
   
   /* Clear slot array first */
   memset(SlotArray, 0x00, sizeof(SlotArray));
   for(wSlot = 0; wSlot < SLOT_MAX_CNT; wSlot++)
   {
      pSlot = &SlotArray[wSlot];

      /* 
       * For compatibility with older version check for 
       * "SlotXX.key" and "SlotXXX.key"
       */      
      if (wSlot < 100)
      {
         /* Version which supports only 0 to 99 slots */
         snprintf(SlotName, sizeof(SlotName), "SD0:/eks/slot%02d.key", wSlot);
         fd = _open(SlotName, _O_BINARY | _O_RDONLY);
         if (-1 == fd)
         {
            /* Version which supports more than 99 slots */
            snprintf(SlotName, sizeof(SlotName), "SD0:/eks/slot%03d.key", wSlot);
            fd = _open(SlotName, _O_BINARY | _O_RDONLY);
         }
      }
      else
      {
         snprintf(SlotName, sizeof(SlotName), "SD0:/eks/slot%d.key", wSlot);
         fd = _open(SlotName, _O_BINARY | _O_RDONLY);
      }   
      
      if (fd != -1)
      {
         rc = _read(fd, pSlot, sizeof(ES3_SLOT));
         _close(fd);
         if (rc != (int)sizeof(ES3_SLOT))
         {
            /* Error, no slot data */
            memset(pSlot, 0x00, sizeof(ES3_SLOT));
         }
         else
         {
            rc = SlotDecrypt(pSlot);
            if (rc != ES3_OK)
            {
               /* Error, no slot data */
               memset(pSlot, 0x00, sizeof(ES3_SLOT));
            }
         }
      } /* end open file */
   } /* end for(wSlot = 0; wSlot < SLOT_MAX_CNT; wSlot++) */
   
   /* Check the first slot for ROOT_OF_TRUST */
   if (0 == strcmp((char*)SlotArray[0].Name, ROOT_OF_TRUST))
   {
      rc = ES3_OK;
      
      /* Unlock user too */
      UserUnlock();
   }
   else
   {
      rc = ES3_ERROR;
   }
   
   return(rc);
} /* EKSUnlock */

/*************************************************************************/
/*  EKSCheckInit                                                         */
/*                                                                       */
/*  Check if an EKS is available.                                        */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void EKSCheckInit (void)
{
   int fd;
   
   /* Read "key" */
   fd = _open("SD0:/eks/eks.key", _O_BINARY | _O_RDONLY);
   if (fd != -1)
   {
      _close(fd);
   
      /* "key" is available, EKS is locked */
      nEKSStatus = STATUS_LOCKED;
   }
   else
   {
      /* No "key", EKS must init */
      nEKSStatus = STATUS_MUST_INIT;
   }

} /* EKSCheckInit */

/*************************************************************************/
/*  EKSFirstInit                                                         */
/*                                                                       */
/*  In    : pPass, PassLen                                               */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int EKSFirstInit (char *pPass, size_t PassLen)
{
   int                        rc = ES3_ERR_EKS_PATH;
   FRESULT                    res;
   int                        fd;
   static mbedtls_aes_context ctx;
   static uint8_t             data[AES_DATA_BYTES_CNT];
   

   res = f_mkdir("eks");
   if ((FR_OK == res) || (FR_EXIST == res))
   {
      rc = EKSCreateKey(pPass, PassLen);
      if (rc != 0)
      {
         rc = ES3_ERR_PKCS5;
      }
      else
      {
         /* Encrypt data */
         tal_CPURngHardwarePoll(data, sizeof(data));
         snprintf((char*)data, sizeof(data), "%s", EKSTest);
         
         mbedtls_aes_init(&ctx);
         mbedtls_aes_setkey_enc(&ctx, EKSKey, (EKS_KEY_LEN*8));
         rc = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, 
                                    (uint8_t*)data,
                                    (uint8_t*)data);
         mbedtls_aes_free(&ctx);
      
         /* Check for AES error */
         if (rc != 0)
         {
            rc = ES3_ERR_AES;
         }
         else
         {
            /* No AES error, write the "key" */
            rc = ES3_ERR_EKS_KEY_WRITE; 
            fd = _open("SD0:/eks/eks.key", _O_BINARY | _O_WRONLY | _O_CREATE_ALWAYS);
            if (fd != -1)
            {
               rc = _write(fd, data, sizeof(data));
               _close(fd);
            
               /* Check write */
               if (rc == (int)sizeof(data))
               {
                  rc = SlotCreate(0, ROOT_OF_TRUST);
               }
            }
         }
      }            
   }

   return(rc);
} /* EKSFirstInit */

/*************************************************************************/
/*  CheckKeyNameRules                                                    */
/*                                                                       */
/*  In    : pPass                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int CheckKeyNameRules (char *pPass)
{
   int rc = ES3_OK;
   
   /* Check key rules, only letters and numbers */   
   if (strlen(pPass) > KEY_NAME_MAX)
   {
      rc = ES3_ERR_KEY_POLICY;
   }
   else
   {
      while (*pPass != 0)
      {
         /* Check uppercase */
         if      ((*pPass >= 'A') && (*pPass <= 'Z'))
         {
            /* Do nothing */
         }
         else if ((*pPass >= '0') && (*pPass <= '9'))
         {
            /* Do nothing */
         }
         
         /* " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~" */
         /* https://owasp.org/www-community/password-special-characters */
         
         /* Check symbols " !"#$%&'()*+,-./" */
         else if ((*pPass >= 0x20) && (*pPass <= 0x2F))
         {
            rc = ES3_ERR_KEY_POLICY;
            break;
         }
         /* Check symbols ":;<=>?@" */
         else if ((*pPass >= 0x3A) && (*pPass <= 0x40))
         {
            rc = ES3_ERR_KEY_POLICY;
            break;
         }
         /* Check symbols "[\]^_`" */
         else if ((*pPass >= 0x5B) && (*pPass <= 0x60))
         {
            rc = ES3_ERR_KEY_POLICY;
            break;
         }
         /* Check symbols "{|}~" */
         else if ((*pPass >= 0x7B) && (*pPass <= 0x7E))
         {
            rc = ES3_ERR_KEY_POLICY;
            break;
         }
         
         pPass++;
      }
   }
      
   return(rc);
} /* CheckKeyNameRules */

/*************************************************************************/
/*  CheckPasswordRules                                                   */
/*                                                                       */
/*  In    : pPass                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int CheckPasswordRules (char *pPass)
{
   int      rc = ES3_ERR_PASS_POLICY;
   uint8_t bFlags = 0;

   #define PASS_MASK_OK 0x1F
   
   if (strlen(pPass) >= 8)
   {
      bFlags |= SIZE_OK;
      
      while (*pPass != 0)
      {
         /* Check uppercase */
         if      ((*pPass >= 'A') && (*pPass <= 'Z'))
         {
            bFlags |= UPPERCASE_OK;
         }
         /* Check lowercase */
         else if ((*pPass >= 'a') && (*pPass <= 'z'))
         {
            bFlags |= LOWERCASE_OK;
         }
         /* Check numbers */
         else if ((*pPass >= '0') && (*pPass <= '9'))
         {
            bFlags |= NUMBER_OK;
         }
         
         /* " !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~" */
         /* https://owasp.org/www-community/password-special-characters */
         
         /* Check symbols " !"#$%&'()*+,-./" */
         else if ((*pPass >= 0x20) && (*pPass <= 0x2F))
         {
            bFlags |= SYMBOL_OK;
         }
         /* Check symbols ":;<=>?@" */
         else if ((*pPass >= 0x3A) && (*pPass <= 0x40))
         {
            bFlags |= SYMBOL_OK;
         }
         /* Check symbols "[\]^_`" */
         else if ((*pPass >= 0x5B) && (*pPass <= 0x60))
         {
            bFlags |= SYMBOL_OK;
         }
         /* Check symbols "{|}~" */
         else if ((*pPass >= 0x7B) && (*pPass <= 0x7E))
         {
            bFlags |= SYMBOL_OK;
         }
         
         pPass++;
      }
   }
      
   /* Check password policy requirements */
   if (PASS_MASK_OK == bFlags)
   {
      rc = 0;
   }
   
   return(rc);
} /* CheckPasswordRules */

/*************************************************************************/
/*  Init                                                                 */
/*                                                                       */
/*  In    : pPass                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int Init (char *pPass)
{
   int    rc;
   size_t PassLen = strlen(pPass);

   rc = CheckPasswordRules(pPass);
   if (ES3_OK == rc)
   {
      rc = EKSFirstInit(pPass, PassLen);
      if (ES3_OK == rc)
      { 
         nEKSStatus = STATUS_UNLOCKED;
      }   
   }
   else
   {
      rc = ES3_ERROR;
   }
   
   return(rc);
} /* Init */

/*************************************************************************/
/*  Lock                                                                 */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int Lock (void)
{
   int rc = ES3_OK;
   
   nEKSStatus = STATUS_LOCKED;

   /* Clear slot, user data and key */
   memset(SlotArray, 0x00, sizeof(SlotArray));
   memset(UserArray, 0x00, sizeof(UserArray));
   memset(EKSKey, 0x00, sizeof(EKSKey));
   
   return(rc);
} /* Lock */

/*************************************************************************/
/*  Unlock                                                               */
/*                                                                       */
/*  In    : pPass                                                        */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int Unlock (char *pPass)
{
   int                        rc;
   size_t                     PassLen = strlen(pPass);
   int                        fd;
   static mbedtls_aes_context ctx;
   static uint8_t             data[AES_DATA_BYTES_CNT];


   /* 
    * Check if the key is the correct one 
    */
   
   /* Generate the key */
   rc = EKSCreateKey(pPass, PassLen);
   if (rc != 0) GOTO_END(ES3_ERROR);

   /* Read the key */   
   fd = _open("SD0:/eks/eks.key", _O_BINARY | _O_RDONLY);
   if (-1 == fd) GOTO_END(ES3_ERROR);
   _read(fd, data, sizeof(data));
   _close(fd);
         
   /* Decrypt the key */
   mbedtls_aes_init(&ctx);
   mbedtls_aes_setkey_dec(&ctx, EKSKey, (EKS_KEY_LEN*8));
   rc = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, 
                              (uint8_t*)data,
                              (uint8_t*)data);
   mbedtls_aes_free(&ctx);

   if (rc != 0) GOTO_END(ES3_ERR_PASS_WRONG);
         
   /* Compare the key */
   if (memcmp(data, EKSTest, sizeof(EKSTest)) != 0) GOTO_END(ES3_ERR_PASS_WRONG);

   /* The key is correct, unlock the EKS now */   
   rc = EKSUnlock();
   if (rc != 0) GOTO_END(ES3_ERROR);
   
   nEKSStatus = STATUS_UNLOCKED;

end:
   return(rc);
} /* Unlock */

/*************************************************************************/
/*  JSONSendError                                                        */
/*                                                                       */
/*  In    : hs, nError, pMsg                                             */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
static void JSONSendError (HTTPD_SESSION *hs, int nError)
{
   s_puts("{", hs->s_stream);
   
   if (0 == nError)
   {
      s_puts("\"err\":0,\"msg\":\"none\"", hs->s_stream);
   }
   else
   {
      s_printf(hs->s_stream, "\"err\":%d,\"msg\":\"error\"", nError);
   }

   s_puts("}", hs->s_stream);
   s_flush(hs->s_stream);

} /* JSONSendError */

/*************************************************************************/
/*  ssi_is_locked                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int ssi_is_locked (HTTPD_SESSION *hs)
{
   s_printf(hs->s_stream, "%d", nEKSStatus);
   s_flush(hs->s_stream);

   return(0);
} /* ssi_is_locked */

/*************************************************************************/
/*  cgi_status                                                           */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_status (HTTPD_SESSION *hs)
{
   IP_WEBS_CGISendHeader(hs);

   s_puts("{", hs->s_stream);
   s_printf(hs->s_stream, "\"locked\":%d", nEKSStatus);
   s_puts("}", hs->s_stream);
   s_flush(hs->s_stream);
   
   return(0);
} /* cgi_status */

/*************************************************************************/
/*  cgi_init_eks                                                         */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_init_eks (HTTPD_SESSION *hs)
{
   int      rc;
   size_t   olen;
   json_t  JSON;   
   char   *pPass;

   OS_RES_LOCK(&Sema);
   
   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pPass = IP_JSON_GetString(&JSON, "pass");
   if (NULL == pPass) GOTO_END(ES3_ERROR);

   rc = mbedtls_base64_decode(pPass, strlen(pPass), &olen, pPass, strlen(pPass)); /*lint !e64*/
   if (rc != 0) GOTO_END(ES3_ERROR);
   pPass[olen] = 0;

   /* This function is only allowed if the status is STATUS_MUST_INIT. If not => ERROR */
   if (STATUS_MUST_INIT != nEKSStatus) GOTO_END(ES3_ERR_NO_INIT);
   
   rc = Init(pPass);
   
end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_init_eks */

/*************************************************************************/
/*  cgi_lock_eks                                                         */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_lock_eks (HTTPD_SESSION *hs)
{
   int     rc;
   json_t  JSON;   

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   rc = Lock();
   if (rc != ES3_OK) GOTO_END(ES3_ERROR);
   
end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_lock_eks */

/*************************************************************************/
/*  cgi_unlock_eks                                                       */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_unlock_eks (HTTPD_SESSION *hs)
{
   int      rc;
   size_t   olen;
   json_t  JSON;   
   char   *pPass;

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pPass = IP_JSON_GetString(&JSON, "pass");
   if (NULL == pPass) GOTO_END(ES3_ERROR);

   rc = mbedtls_base64_decode(pPass, strlen(pPass), &olen, pPass, strlen(pPass)); /*lint !e64*/
   if (rc != 0) GOTO_END(ES3_ERROR);
   pPass[olen] = 0;
   
   /* Check for LOCK mode */
   if (STATUS_LOCKED != nEKSStatus) GOTO_END(ES3_ERR_NO_LOCKED);

   rc = Unlock(pPass);

end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_unlock_eks */

/*************************************************************************/
/*  cgi_create_eks                                                       */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_create_eks (HTTPD_SESSION *hs)
{
   int       rc;
   uint16_t wSlot;
   uint16_t wIndex;
   char    *pSlot;
   char    *pKey;
   char    *pChar;
   json_t    JSON;   

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pSlot = IP_JSON_GetString(&JSON, "slot");
   if (NULL == pSlot) GOTO_END(ES3_ERROR);
   if (0 == *pSlot) GOTO_END(ES3_ERROR);
   
   wSlot = (uint8_t)atoi(pSlot);
   if ((0 == wSlot) || (wSlot >= SLOT_MAX_CNT)) GOTO_END(ES3_ERROR);

   pKey = IP_JSON_GetString(&JSON, "key");
   if (NULL == pKey) GOTO_END(ES3_ERROR);
   if (0 == *pKey) GOTO_END(ES3_ERROR);
   
   /* Convert to lowercase */
   pChar = pKey;
   while (*pChar != 0)
   {
      *pChar = (char)tolower(*pChar);
      pChar++;
   }
   
   /* Check for UNLOCK mode */
   if (STATUS_UNLOCKED != nEKSStatus) GOTO_END(ES3_ERR_NO_UNLOCK);

   /* Check if slot is in use */
   if (SlotArray[wSlot].dID != MBEDTLS_ECP_DP_NONE) GOTO_END(ES3_ERROR);

   /* Check key name policy */   
   rc = CheckKeyNameRules(pKey);
   if (ES3_OK == rc)
   {
      /* Check if the key is still available */   
      for(wIndex = 0; wIndex < SLOT_MAX_CNT; wIndex++)
      {
         /* Check if slot is in use */
         if (SlotArray[wIndex].dID != MBEDTLS_ECP_DP_NONE)
         {
            /* Check if the key is still available */
            if (0 == strcmp((char*)SlotArray[wIndex].Name, pKey)) GOTO_END(ES3_ERR_KEY_DUPLICAT);
         }
      }
   
      /* Create new key */
      rc = SlotCreate(wSlot, pKey);
   }      

end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_create_eks */

/*************************************************************************/
/*  cgi_disable_slot                                                     */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_disable_slot (HTTPD_SESSION *hs)
{
   int       rc;
   uint16_t wSlot;
   char    *pSlot;
   json_t    JSON;   

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pSlot = IP_JSON_GetString(&JSON, "slot");
   if (NULL == pSlot) GOTO_END(ES3_ERROR);
   
   wSlot = (uint8_t)atoi(pSlot);
   if ((0 == wSlot) || (wSlot >= SLOT_MAX_CNT)) GOTO_END(ES3_ERROR);
   
   /* Check for UNLOCK mode */
   if (STATUS_UNLOCKED != nEKSStatus) GOTO_END(ES3_ERR_NO_UNLOCK);

   /* Check if slot is used and enabled */   
   if ((SlotArray[wSlot].dID != MBEDTLS_ECP_DP_NONE) && (SLOT_FLAG_ENABLE == (SlotArray[wSlot].dFlags & SLOT_FLAG_ENABLE)))
   {
      SlotArray[wSlot].dFlags &= ~SLOT_FLAG_ENABLE;
      
      rc = SlotUpdate(wSlot);
   }
   else
   {
      rc = ES3_ERROR;
   }
   
end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_disable_slot */

/*************************************************************************/
/*  cgi_enable_slot                                                      */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_enable_slot (HTTPD_SESSION *hs)
{
   int       rc;
   uint16_t wSlot;
   char    *pSlot;
   json_t    JSON;   

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pSlot = IP_JSON_GetString(&JSON, "slot");
   if (NULL == pSlot) GOTO_END(ES3_ERROR);
   
   wSlot = (uint8_t)atoi(pSlot);
   if ((0 == wSlot) || (wSlot >= SLOT_MAX_CNT)) GOTO_END(ES3_ERROR);

   /* Check for UNLOCK mode */
   if (STATUS_UNLOCKED != nEKSStatus) GOTO_END(ES3_ERR_NO_UNLOCK);

   /* Check if slot is used and disabled */   
   if ((SlotArray[wSlot].dID != MBEDTLS_ECP_DP_NONE) && (0 == (SlotArray[wSlot].dFlags & SLOT_FLAG_ENABLE)))
   {
      SlotArray[wSlot].dFlags |= SLOT_FLAG_ENABLE;
      
      rc = SlotUpdate(wSlot);
   }
   else
   {
      rc = ES3_ERROR;
   }
   
end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_enable_slot */

/*************************************************************************/
/*  cgi_pkey_slot                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_pkey_slot (HTTPD_SESSION *hs)
{
   int         rc;
   uint16_t   wSlot = 0;
   char      *pSlot;
   char      *pChar;
   json_t      JSON; 

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pSlot = IP_JSON_GetString(&JSON, "slot");
   if (NULL == pSlot) GOTO_END(ES3_ERROR);
   
   wSlot = (uint8_t)atoi(pSlot);
   if (wSlot >= SLOT_MAX_CNT) GOTO_END(ES3_ERROR);

   /* Check for UNLOCK mode */
   if (STATUS_UNLOCKED != nEKSStatus) GOTO_END(ES3_ERR_NO_UNLOCK);

   /* Check if slot is used and enabled */   
   if ((SlotArray[wSlot].dID != MBEDTLS_ECP_DP_NONE) && (SLOT_FLAG_ENABLE == (SlotArray[wSlot].dFlags & SLOT_FLAG_ENABLE)))
   {
      rc = ES3_OK;
   }
   else
   {
      rc = ES3_ERROR;
   }
   
end: 

   if (ES3_OK == rc)
   {
      /* Output public key */ 
      pChar = (char*)SlotArray[wSlot].Pub;
      while (*pChar != 0)
      {
         s_putchar(hs->s_stream, *pChar);
         if (0x0A == *pChar)
         {
            s_flush(hs->s_stream);
         }
         pChar++;   
      }
      
      s_flush(hs->s_stream);
   }
   else
   {
      s_printf(hs->s_stream, "An internal error has occurred: %d\r\n", rc);
      s_flush(hs->s_stream);
   }

   IP_JSON_Delete(&JSON);

   OS_RES_FREE(&Sema);
      
   return(0);
} /* cgi_pkey_slot */

/*************************************************************************/
/*  cgi_key_user                                                         */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_key_user (HTTPD_SESSION *hs)
{
   int        rc;
   uint8_t   bIndex = 0;
   char     *pIndex;
   ES3_USER *pUser = NULL;
   json_t     JSON; 

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pIndex = IP_JSON_GetString(&JSON, "index");
   if (NULL == pIndex) GOTO_END(ES3_ERROR);
   if (0 == *pIndex) GOTO_END(ES3_ERROR);
   
   bIndex = (uint8_t)atoi(pIndex);
   if (bIndex >= USER_MAX_CNT) GOTO_END(ES3_ERROR);

   /* Check if user is available */
   pUser = &UserArray[bIndex];
   if ((USER_MAGIC1 == pUser->dMagic1) &&
       (USER_MAGIC2 == pUser->dMagic2))
   {
      rc = ES3_OK;
   }
   else
   {
      rc = ES3_ERR_NOT_AVAILABLE;
   }
   
end: 

   if ((ES3_OK == rc) && (pUser != NULL))
   {
      /* Output key */ 
      for(int x = 0; x < (int)strlen(pUser->PubKey); x++)
      {
         s_printf(hs->s_stream, "%c", pUser->PubKey[x]);
      }
      s_flush(hs->s_stream);
   }
   else
   {
      s_printf(hs->s_stream, "An internal error has occurred: %d\r\n", rc);
      s_flush(hs->s_stream);
   }

   IP_JSON_Delete(&JSON);

   OS_RES_FREE(&Sema);
      
   return(0);
} /* cgi_key_user */

/*************************************************************************/
/*  cgi_del_user                                                         */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_del_user (HTTPD_SESSION *hs)
{
   int        rc;
   uint8_t   bIndex;
   char     *pIndex;
   ES3_USER *pUser;
   json_t     JSON;   

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pIndex = IP_JSON_GetString(&JSON, "index");
   if (NULL == pIndex) GOTO_END(ES3_ERROR);
   if (0 == *pIndex) GOTO_END(ES3_ERROR);
   
   bIndex = (uint8_t)atoi(pIndex);
   if (bIndex >= USER_MAX_CNT) GOTO_END(ES3_ERROR);

   /* Check if user is available */
   pUser = &UserArray[bIndex];
   if ((USER_MAGIC1 == pUser->dMagic1) &&
       (USER_MAGIC2 == pUser->dMagic2))
   {
      rc = UserDel(bIndex, pUser);
   }
   else
   {
      rc = ES3_ERR_NOT_AVAILABLE;
   }

end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_del_user */

/*************************************************************************/
/*  cgi_add_user                                                         */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_add_user (HTTPD_SESSION *hs)
{
   int      rc;
   uint8_t bIndex;
   char   *pIndex;
   char   *pUser;
   json_t   JSON;   

   OS_RES_LOCK(&Sema);

   IP_WEBS_CGISendHeader(hs);

   rc = IP_JSON_ParseHS(hs, &JSON, 8);
   if (-1 == rc) GOTO_END(ES3_ERROR);

   pIndex = IP_JSON_GetString(&JSON, "index");
   if (NULL == pIndex) GOTO_END(ES3_ERROR);
   if (0 == *pIndex) GOTO_END(ES3_ERROR);
   
   bIndex = (uint8_t)atoi(pIndex);
   if (bIndex >= USER_MAX_CNT) GOTO_END(ES3_ERROR);

   pUser = IP_JSON_GetString(&JSON, "user");
   if (NULL == pUser) GOTO_END(ES3_ERROR);
   if (0 == *pUser) GOTO_END(ES3_ERROR);

   /* Add new key */
   rc = UserAdd(bIndex, pUser);

end:  

   IP_JSON_Delete(&JSON);
   JSONSendError(hs, rc);

   OS_RES_FREE(&Sema);
   
   return(0);
} /* cgi_add_user */

/*************************************************************************/
/*  cgi_eks_table                                                        */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_eks_table (HTTPD_SESSION *hs)
{
   uint16_t  wSlot;
   uint16_t  wDim;
   ES3_SLOT *pSlot = NULL;

   OS_RES_LOCK(&Sema);
   
   IP_WEBS_CGISendHeader(hs);
   
   if (nEKSStatus != STATUS_UNLOCKED)
   {
      s_printf(hs->s_stream, "<tr align=\"center\">\r\n");
      s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");
      s_printf(hs->s_stream, "  <td colspan=\"4\">The encrypted keystore is currently still locked. Please unlock first.</td>\r\n");
      s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");
      s_printf(hs->s_stream, "</tr>\r\n");
   }
   else
   {
      wDim = 0;
      for(wSlot = 0; wSlot < SLOT_MAX_CNT; wSlot++)
      {
         if (0 == (wDim & 0x01))
         {
            s_printf(hs->s_stream, "<tr>\r\n");
         }
         else
         {
            s_printf(hs->s_stream, "<tr class=\"dim\">\r\n");
         }


         s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");
         s_printf(hs->s_stream, "  <td>&nbsp;%03d</td>\r\n", wSlot);
         
         pSlot = &SlotArray[wSlot];
         /* Check for a valid slot */
         if (pSlot->dID != MBEDTLS_ECP_DP_NONE)
         {
            s_printf(hs->s_stream, "  <td>%s</td>\r\n", pSlot->Name);
            s_printf(hs->s_stream, "  <td>secp256r1 (NIST P-256)</td>\r\n");
            
            /* Special handling for slot 0 */
            if (0 == wSlot)
            {
               /* Root of Trust */
               s_printf(hs->s_stream, "  <td><a href=\"pkey.htm?slot=%d&key=%s\">Public Key</a></td>\r\n", wSlot, pSlot->Name);
            }
            else
            {
               /* Check if slot is enabled */
               if (SLOT_FLAG_ENABLE == (pSlot->dFlags & SLOT_FLAG_ENABLE))
               {
                  /* Slot is enabled */
                  s_printf(hs->s_stream, "  <td><a href=\"disable.htm?slot=%d&key=%s\">Disable</a>, <a href=\"pkey.htm?slot=%d&key=%s\">Public Key</a></td>\r\n", wSlot, pSlot->Name, wSlot, pSlot->Name);
               }   
               else
               {
                  /* Slot is disabled */
                  s_printf(hs->s_stream, "  <td><a href=\"enable.htm?slot=%d&key=%s\">Enable</a></td>\r\n", wSlot, pSlot->Name);
               }
            }   
         }
         else
         {
            s_printf(hs->s_stream, "  <td>--- Empty Slot ---</td>\r\n");
            s_printf(hs->s_stream, "  <td>---</td>\r\n");
            s_printf(hs->s_stream, "  <td><a href=\"create.htm?slot=%d\">Create</a></td>\r\n", wSlot);
         }

         s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");
         s_printf(hs->s_stream, "</tr>\r\n");

         s_flush(hs->s_stream);

         wDim++; 
         
      } /* end for */
   }      

   s_flush(hs->s_stream);

   OS_RES_FREE(&Sema);

   return(0);
} /* cgi_eks_table */

/*************************************************************************/
/*  cgi_user_table                                                       */
/*                                                                       */
/*  In    : hs                                                           */
/*  Out   : none                                                         */
/*  Return: 0 = OK / -1 = ERROR                                          */
/*************************************************************************/
static int cgi_user_table (HTTPD_SESSION *hs)
{
   uint8_t   bIndex;
   uint16_t  wDim;
   ES3_USER *pUser = NULL;

   OS_RES_LOCK(&Sema);
   
   IP_WEBS_CGISendHeader(hs);
   
   if (nEKSStatus != STATUS_UNLOCKED)
   {
      s_printf(hs->s_stream, "<tr align=\"center\">\r\n");
      s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");
      s_printf(hs->s_stream, "  <td colspan=\"3\">The encrypted keystore is currently still locked. Please unlock first.</td>\r\n");
      s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");
      s_printf(hs->s_stream, "</tr>\r\n");
   }
   else
   {
      wDim = 0;
      for(bIndex = 0; bIndex < USER_MAX_CNT; bIndex++)
      {
         if (0 == (wDim & 0x01))
         {
            s_printf(hs->s_stream, "<tr>\r\n");
         }
         else
         {
            s_printf(hs->s_stream, "<tr class=\"dim\">\r\n");
         }

         s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");

         pUser = &UserArray[bIndex];
         /* Check for a valid user */
         if ((USER_MAGIC1 == pUser->dMagic1) &&
             (USER_MAGIC2 == pUser->dMagic2))
         {
            s_printf(hs->s_stream, "  <td>%s</td>\r\n", pUser->User);
            
            
            /* Output fingerprint */
            s_printf(hs->s_stream, "  <td>");
            
            for(int x = 0; x < 16; x++)
            {
               s_printf(hs->s_stream, "%02X", pUser->Hash[x]);
            }
            s_flush(hs->s_stream);
            
            s_printf(hs->s_stream, "</td>\r\n");
            s_printf(hs->s_stream, "  <td><a href=\"ukey.htm?user=%d&name=%s\">Public Key</a>, <a href=\"delete.htm?user=%d&name=%s\">Delete</a></td>\r\n", bIndex, pUser->User, bIndex, pUser->User);
         }
         else
         {
            s_printf(hs->s_stream, "  <td>---</td>\r\n");
            s_printf(hs->s_stream, "  <td>---</td>\r\n");
            s_printf(hs->s_stream, "  <td><a href=\"add.htm?user=%d\">Add</a></td>\r\n", bIndex);
         }

         s_printf(hs->s_stream, "  <td>&nbsp;</td>\r\n");
         s_printf(hs->s_stream, "</tr>\r\n");

         s_flush(hs->s_stream);

         wDim++; 
         
      } /* end for */
   }
   
   s_flush(hs->s_stream);

   OS_RES_FREE(&Sema);

   return(0);
} /* cgi_user_table */

/*
 * SSI variable list
 */
static const SSI_EXT_LIST_ENTRY SSIList[] =
{
   { "es3_is_locked",   ssi_is_locked },

   {NULL, NULL}
};

/*
 * CGI variable list
 */
static const CGI_LIST_ENTRY CGIList[] =
{
   { "cgi-bin/es3_status.cgi",     cgi_status       },
   { "cgi-bin/es3_init.cgi",       cgi_init_eks     },
   { "cgi-bin/es3_lock.cgi",       cgi_lock_eks     },
   { "cgi-bin/es3_unlock.cgi",     cgi_unlock_eks   },
   { "cgi-bin/es3_create.cgi",     cgi_create_eks   },
   { "cgi-bin/es3_disable.cgi",    cgi_disable_slot },
   { "cgi-bin/es3_enable.cgi",     cgi_enable_slot  },
   { "cgi-bin/es3_pkey.cgi",       cgi_pkey_slot    },

   { "cgi-bin/es3_key.cgi",        cgi_key_user     },
   { "cgi-bin/es3_del.cgi",        cgi_del_user     },
   { "cgi-bin/es3_add.cgi",        cgi_add_user     },
   
   { "cgi-bin/es3_eks_table.cgi",  cgi_eks_table    },  
   { "cgi-bin/es3_user_table.cgi", cgi_user_table   },

   {NULL, NULL}
};

/*************************************************************************/
/*  VerifyRPC                                                            */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg                                               */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static int VerifyRPC (es3_msg_t *pRxMsg, es3_msg_t *pTxMsg)
{  
   int                      rc = ES3_RPC_ERROR;
   uint16_t                wSlot;
   uint8_t                 bUser;
   ES3_SLOT               *pSlot = NULL;
   ES3_USER               *pUser = NULL;
   uint8_t                *p;
   size_t                   len;
   mbedtls_pk_context       ctx;
   mbedtls_sha256_context   sha_ctx;
   mbedtls_entropy_context  entropy;
   mbedtls_ctr_drbg_context ctr_drbg;
   uint8_t                  Hash[32];
   size_t                   SigLen;
   
   /*
    * 1. Check if EKS is unlocked
    * 2. Check if requested slot is available
    * 3. Check if requested user is valid
    * 4. Get public key from the user
    * 5. Create SHA256 hash from the "Data"
    * 6. Check for valid signature of the request with the public key of the user
    */

   /* Prepare key generation */
   mbedtls_sha256_init(&sha_ctx);
   mbedtls_pk_init(&ctx);
   mbedtls_ctr_drbg_init(&ctr_drbg);
   mbedtls_entropy_init(&entropy);
   
   
   /* 
    * 1. Check if EKS is unlocked 
    */ 
   if (nEKSStatus != STATUS_UNLOCKED) GOTO_END(ES3_RPC_ERR_LOCKED);


   /* 
    * 2. Check if slot is available 
    */
   rc = ES3_RPC_ERROR; 
   for(wSlot = 0; wSlot < SLOT_MAX_CNT; wSlot++)
   {
      /* Get slot data */
      pSlot = &SlotArray[wSlot];
      
      /* Check for a valid slot */
      if (pSlot->dID != MBEDTLS_ECP_DP_NONE)
      {
         /* Check slot name */
         if (0 == strcmp(pSlot->Name, pRxMsg->Data.cSign.Slot))
         {
            rc = ES3_RPC_OK;
            break;
         }
      }
   }
   if (rc != ES3_RPC_OK) GOTO_END(ES3_RPC_ERR_SLOT);

   
   /*
    * 3. Check if user is valid
    */
   rc = ES3_RPC_ERROR;
   for(bUser = 0; bUser < USER_MAX_CNT; bUser++)
   {
      /* Get user data */
      pUser = &UserArray[bUser];
      
      /* Check for a valid user */
      if ((USER_MAGIC1 == pUser->dMagic1) &&
          (USER_MAGIC2 == pUser->dMagic2))
      {
         /* Check user name */
         if (0 == strcmp(pUser->User, pRxMsg->Header.User))
         {
            rc = ES3_RPC_OK;
            break;
         }
      }
   }
   if (rc != ES3_RPC_OK) GOTO_END(ES3_RPC_ERR_USER);

   
   /*
    * 4. Get public key from the user
    */   
    
   /* Check if this is a valid key */
   p   = pUser->PubKeyRaw;
   len = pUser->wPubKeyRawLen;
   rc = mbedtls_pk_parse_subpubkey(&p, p + len, &ctx);
   if (rc != 0) GOTO_END(ES3_RPC_ERR_ECC);
   
   /* At this point we have a valid ECC key */


   /*
    * 5. Create SHA256 hash from the "Data"
    */

   /* Start the HASH */
   mbedtls_sha256_starts(&sha_ctx, 0);

   /* Calculate the hash over the data */
   len = pRxMsg->Header.Len;
   mbedtls_sha256_update(&sha_ctx, (uint8_t*)&pRxMsg->Data, len);

   /* Get result */
   mbedtls_sha256_finish(&sha_ctx, Hash);    
   
   
   /*
    * 6. Check for valid signature of the "Data"
    */
   SigLen = (size_t)pRxMsg->Header.SigLen;   /*lint !e571*/
   rc = mbedtls_pk_verify(&ctx, MBEDTLS_MD_SHA256, Hash, 0, pRxMsg->Header.Sig, SigLen);
   if (rc != 0) GOTO_END(ES3_RPC_ERR_ECC);

   /* At this point we have a valid signated signing request */
   
   rc = ES3_RPC_OK;
    
end:

   pTxMsg->Header.Result = rc;


   /* Free the mbedTLS content */
   mbedtls_pk_free(&ctx);
   mbedtls_ctr_drbg_free(&ctr_drbg);
   mbedtls_entropy_free(&entropy);
   mbedtls_sha256_free(&sha_ctx);   
   
   return(rc);
} /* VerifyRPC */

/*************************************************************************/
/*  HandleSignReq                                                        */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg                                               */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandleSignReq (es3_msg_t *pRxMsg, es3_msg_t *pTxMsg)
{
   int                      rc = ES3_RPC_ERROR;
   uint16_t                wSlot;
   ES3_SLOT               *pSlot = NULL;
   size_t                   len;
   mbedtls_pk_context       ctx;
   mbedtls_entropy_context  entropy;
   mbedtls_ctr_drbg_context ctr_drbg;
   size_t                   SigLen;
   
   /*
    * 1. Check if EKS is unlocked
    * 2. Check if requested slot is available
    * 3. Check if requested user is valid
    * 4. Get public key from the user
    * 5. Create SHA256 hash from the "Data"
    * 6. Check for valid signature of the request with the public key of the user
    * 7. Read private key of the slot
    * 8. Create signature for the given hash 
    */

   /* Prepare key generation */
   mbedtls_pk_init(&ctx);
   mbedtls_ctr_drbg_init(&ctr_drbg);
   mbedtls_entropy_init(&entropy);
   
   /*
    * 1 to 6 was done before by VerifyRPC
    */

   /* At this point we have a valid signated signing request */


   /* 
    * Check if slot is available 
    */
   for(wSlot = 0; wSlot < SLOT_MAX_CNT; wSlot++)
   {
      /* Get slot data */
      pSlot = &SlotArray[wSlot];
      
      /* Check for a valid slot */
      if (pSlot->dID != MBEDTLS_ECP_DP_NONE)
      {
         /* Check slot name */
         if (0 == strcmp(pSlot->Name, pRxMsg->Data.cSign.Slot))
         {
            rc = ES3_RPC_OK;
            break;
         }
      }
   }
   if (rc != ES3_RPC_OK) GOTO_END(ES3_RPC_ERR_SLOT);
   

   /* 
    * 7. Read private key 
    */
   len = strlen((char*)pSlot->Priv) + 1;
   rc = mbedtls_pk_parse_key(&ctx, pSlot->Priv, len, NULL, 0,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
   if(rc != 0) GOTO_END(ES3_RPC_ERR_ECC);

   /* Seed the random generator */
   rc =  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)"TinyES3", 7);
   if(rc != 0) GOTO_END(ES3_RPC_ERR_ECC);


   /* 
    * 8. Create signature for the given hash 
    */
   SigLen = ES3_RPC_SIG_SIZE;
   rc = mbedtls_pk_sign(&ctx, MBEDTLS_MD_SHA256, pRxMsg->Data.cSign.Hash, 0, 
                        pTxMsg->Data.rSign.Sig, sizeof(pTxMsg->Data.rSign.Sig), &SigLen, mbedtls_ctr_drbg_random, &ctr_drbg);
   if(rc != 0) GOTO_END(ES3_RPC_ERR_ECC);

   /* Signature successful created */      
   pTxMsg->Header.Len = ES3_REPLY_SIGN_SIZE;
   memcpy(pTxMsg->Data.rSign.Slot, pRxMsg->Data.cSign.Slot, ES3_RPC_SLOT_SIZE);
   pTxMsg->Data.rSign.SigLen = (uint8_t)SigLen;
    
end:

   pTxMsg->Header.Result = rc;

   /* Free the mbedTLS content */
   mbedtls_pk_free(&ctx);
   mbedtls_ctr_drbg_free(&ctr_drbg);
   mbedtls_entropy_free(&entropy);

} /* HandleSignReq */

/*************************************************************************/
/*  HandlePubReq                                                         */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg                                               */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandlePubReq (es3_msg_t *pRxMsg, es3_msg_t *pTxMsg)
{
   int          rc = ES3_RPC_ERROR;
   uint16_t    wSlot;
   ES3_SLOT   *pSlot = NULL;
   size_t       len;
   
   /*
    * 1. Check if EKS is unlocked
    * 2. Check if requested slot is available
    * 3. Check if requested user is valid
    * 4. Get public key from the user
    * 5. Create SHA256 hash from the "Data"
    * 6. Check for valid signature of the request with the public key of the user
    * 7. Read public key of the slot
    */

   /*
    * 1 to 6 was done before by VerifyRPC
    */

   /* At this point we have a valid signated signing request */


   /* 
    * Check if slot is available 
    */
   for(wSlot = 0; wSlot < SLOT_MAX_CNT; wSlot++)
   {
      /* Get slot data */
      pSlot = &SlotArray[wSlot];
      
      /* Check for a valid slot */
      if (pSlot->dID != MBEDTLS_ECP_DP_NONE)
      {
         /* Check slot name */
         if (0 == strcmp(pSlot->Name, pRxMsg->Data.cSign.Slot))
         {
            rc = ES3_RPC_OK;
            break;
         }
      }
   }
   if (rc != ES3_RPC_OK) GOTO_END(ES3_RPC_ERR_SLOT);
   

   /* 
    * 6. Read public key 
    */
   len = strlen((char*)pSlot->Pub) + 1;
   memset(pTxMsg->Data.rGetPub.Pub, 0x00, ES3_RPC_PUB_SIZE);
   memcpy(pTxMsg->Data.rGetPub.Pub, pSlot->Pub, len);
   pTxMsg->Header.Len = ES3_REPLY_GET_PUB_SIZE;
    
end:

   pTxMsg->Header.Result = rc;

} /* HandlePubReq */

/*************************************************************************/
/*  HandleGetList                                                        */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg                                               */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandleGetList (es3_msg_t *pRxMsg, es3_msg_t *pTxMsg)
{
   uint16_t    wSlot;
   uint8_t     bIndex;
   ES3_SLOT   *pSlot = NULL;
   
   (void)pRxMsg;
   
   /*
    * 1. Check if EKS is unlocked
    * 2. Check if requested slot is available
    * 3. Check if requested user is valid
    * 4. Get public key from the user
    * 5. Create SHA256 hash from the "Data"
    * 6. Check for valid signature of the request with the public key of the user
    * 7. Return list of slots
    */

   /*
    * 1 to 6 was done before by VerifyRPC
    */

   /* At this point we have a valid signated signing request */


   /* 
    * 7. Return list of slots
    */
   memset(pTxMsg->Data.rGetList.SlotArray, 0x00, sizeof(pTxMsg->Data.rGetList.SlotArray));    
    
   bIndex = 0; 
   for(wSlot = 0; wSlot < SLOT_MAX_CNT; wSlot++)
   {
      /* Get slot data */
      pSlot = &SlotArray[wSlot];
      
      /* Check for a valid slot */
      if (pSlot->dID != MBEDTLS_ECP_DP_NONE)
      {
         memcpy(pTxMsg->Data.rGetList.SlotArray[bIndex], pSlot->Name, SLOT_NAME_SIZE);
         bIndex++;
      }
   }

   pTxMsg->Header.Len    = ES3_REPLY_GET_LIST_SIZE;
   pTxMsg->Header.Result = ES3_RPC_OK;

} /* HandleGetList */

/*************************************************************************/
/*  HandleRPC                                                            */
/*                                                                       */
/*  In    : pRxMsg, pTxMsg, RxSize                                       */
/*  Out   : pTxMsg                                                       */
/*  Return: none                                                         */
/*************************************************************************/
static void HandleRPC (es3_msg_t *pRxMsg, es3_msg_t *pTxMsg, int RxSize)
{
   int rc;
   
   /* Copy header */
   memcpy(pTxMsg, pRxMsg, ES3_RPC_HEADER_SIZE);
   
   /* Set default */
   memset(pTxMsg->Header.Sig, 0x00, ES3_RPC_SIG_SIZE);
   pTxMsg->Header.SigLen = 0;
   pTxMsg->Header.Len    = 0;
   pTxMsg->Header.Result = ES3_RPC_ERROR;
   
   /* Test for correct size */
   if (pRxMsg->Header.Len > (uint32_t)(RxSize - (int)ES3_RPC_HEADER_SIZE))
   {
      /* Error, MsgLen to large */
      pTxMsg->Header.Result = ES3_RPC_ERR_LEN;
   }
   else
   {
      rc = VerifyRPC(pRxMsg, pTxMsg);
      if (ES3_OK == rc)
      {
         switch (pRxMsg->Header.Func)
         {
            case ES3_MSG_SIGN:     HandleSignReq(pRxMsg, pTxMsg); break;
            case ES3_MSG_GET_PUB:  HandlePubReq(pRxMsg, pTxMsg);  break;
            case ES3_MSG_GET_LIST: HandleGetList(pRxMsg, pTxMsg); break;
         
            default:
            {
               /* Error, invalid function */
               pTxMsg->Header.Result = ES3_RPC_ERR_FUNC;
               break;
            }
         }
      }         
   }

} /* HandleRPC */

/*************************************************************************/
/*  ES3Task                                                              */
/*                                                                       */
/*  In    : task parameter                                               */
/*  Out   : none                                                         */
/*  Return: never                                                        */
/*************************************************************************/
static void ES3Task (void *arg)
{
   int                Err;
   int                Size;
   int                Socket;
   struct sockaddr_in Server;
   struct sockaddr_in Source;
   int                SourceLen;  
   static uint8_t     RxBuffer[ sizeof(es3_msg_t) ];
   static uint8_t     TxBuffer[ sizeof(es3_msg_t) ];
   es3_msg_t        *pRxMsg;
   es3_msg_t        *pTxMsg;
   
   (void)arg;
   
   /* Setup tx msg */   
   pTxMsg = (es3_msg_t*)TxBuffer;
   

   /* Wait that the IP interface is ready for use */
   while (0 == IP_IF_IsReady(IFACE_ANY))
   {
      OS_TimeDly(100);
   }

   /* Wait some time for the external switch */
   OS_TimeDly(DELAY_AFTER_LINK_MS);
   
   /* Create socket */
   Socket = socket(AF_INET, SOCK_DGRAM, 0);
   TAL_ASSERT(Socket != SOCKET_ERROR);
   
   /* Assign a name (port) to an unnamed socket */
   Server.sin_addr.s_addr = INADDR_ANY;
   Server.sin_port        = htons(ES3_SERVER_PORT);
   Server.sin_family      = AF_INET;

   Err = bind(Socket, (struct sockaddr *)&Server, sizeof(Server)); /*lint !e740*/
   TAL_ASSERT(0 == Err);

   /* 
    * At this point the ServerSocket is 
    * created an can be used 
    */
    
   while(1)
   {
      SourceLen = sizeof(Source);
      Size = recvfrom(Socket, (uint8_t*)RxBuffer, sizeof(RxBuffer), 0,
                      (struct sockaddr *)&Source, (socklen_t*)&SourceLen); /*lint !e740*/

      if ((Size > 0) && (Size > (int)ES3_RPC_HEADER_SIZE))
      {
         pRxMsg = (es3_msg_t*)RxBuffer;
         if( (ES3_RPC_HEADER_MAGIC_1  == pRxMsg->Header.Magic1)  && 
             (ES3_RPC_HEADER_MAGIC_2  == pRxMsg->Header.Magic2)  && 
             (ES3_RPC_SIZEVER         == pRxMsg->Header.SizeVer) )
         {
            HandleRPC(pRxMsg, pTxMsg, Size);

            /* Send response */               
            sendto(Socket, (const char *)pTxMsg, ES3_RPC_HEADER_SIZE + pTxMsg->Header.Len, 0, 
                   (struct sockaddr *)&Source, sizeof(struct sockaddr)); /*lint !e740*/    
         }
      }
                      
      /*
       * No delay at end is needed here, because the recvfrom is blocking.
       */
   }      
   
} /* ES3Task */   

/*=======================================================================*/
/*  All code exported                                                    */
/*=======================================================================*/

/*************************************************************************/
/*  es3_Init                                                             */
/*                                                                       */
/*  Initialize the ES3 functionality of the web server.                  */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
void es3_Init (void)
{
   static int InitDone = 0;
   
   /*lint -save -e506 -e774 -e778*/

   /* Check the correct size of the EKSTest key */
   if( (sizeof(EKSTest) < AES_DATA_BYTES_CNT)         &&
       (0 == (sizeof(ES3_SLOT) % AES_DATA_BYTES_CNT)) &&
       (0 == (sizeof(ES3_USER) % AES_DATA_BYTES_CNT)) &&
       (SLOT_NAME_SIZE == ES3_HEAD_SLOT_SIZE)         &&
       (SLOT_NAME_SIZE == ES3_RPC_SLOT_SIZE)          &&
       (USER_NAME_SIZE == ES3_RPC_USER_SIZE)          &&
       (0 == InitDone)                                )
   { 
      /* Create semaphore */
      OS_RES_CREATE(&Sema);
   
      /* Register SSI and CGI list */
      IP_WEBS_SSIListAdd((SSI_EXT_LIST_ENTRY*)SSIList);
      IP_WEBS_CGIListAdd((CGI_LIST_ENTRY*)CGIList);

      /* Check if a EKS is available */
      EKSCheckInit();
      
      /* Clear slot and user data data first */
      memset(SlotArray, 0x00, sizeof(SlotArray));
      memset(UserArray, 0x00, sizeof(UserArray));
      

      /* Create the ES3 Server task */
      OS_TaskCreate(&TCBES3, ES3Task, NULL, TASK_IP_ES3_PRIORITY,
                    ES3Stack, TASK_IP_ES3_STK_SIZE, "ES3");

      InitDone = 1;
   }      

   /*lint -restore*/
   
} /* es3_Init */

/*************************************************************************/
/*  es3_Lock                                                             */
/*                                                                       */
/*  In    : none                                                         */
/*  Out   : none                                                         */
/*  Return: none                                                         */
/*************************************************************************/
void es3_Lock (void)
{
   if (STATUS_UNLOCKED == nEKSStatus)
   {
      Lock();
   }
   
} /* es3_Lock */

/*lint -restore*/

/*** EOF ***/
