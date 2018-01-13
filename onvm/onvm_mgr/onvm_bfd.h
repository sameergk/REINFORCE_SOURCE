/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2016 George Washington University
 *            2015-2016 University of California Riverside
 *            2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ********************************************************************/


/******************************************************************************

                                 onvm_bfd.h

     This file contains the prototypes for all functions related to BFD
     processing.

******************************************************************************/

#ifndef _ONVM_BFD_H_
#define _ONVM_BFD_H_

/***************************** Header Includes ********************************/
#include "onvm_mgr.h"

/***************************** Globals/Macros *********************************/


/***************************** Data Structures ********************************/
/**************************************************************
* Copyright (c) 2010-2013, Dynamic Network Services, Inc.
* Jake Montgomery (jmontgomery@dyn.com) & Tom Daly (tom@dyn.com)
* Distributed under the FreeBSD License - see LICENSE
***************************************************************/
/**
   Basic headers for the BFD protocol.

   This is based on draft-ietf-bfd-base-10.txt (Jan 5th 2010)
 */
#pragma once

// bfd constants are in a special namespace for clarity

//const uint16_t BasePacketSize = 24; // without the auth data.
#define BasePacketSize (24)

//const uint16_t MaxAuthDataSize = 26; // Keyed SHA1 is the biggest at 26 bytes?
#define MaxAuthDataSize (26)

//const uint16_t AuthHeaderSize = 2; // just the "fixed" info.
#define AuthHeaderSize (2)

//const uint16_t MaxPacketSize = const(BasePacketSize + MaxAuthDataSize + AuthHeaderSize);
#define MaxPacketSize (BasePacketSize + MaxAuthDataSize + AuthHeaderSize)

//const uint16_t ListenPort = 3784;
#define ListenPort (3784)

//const uint8_t TTLValue = 255;
#define TTLValue (255)

//const uint16_t MinSourcePort = 49142U;  // Per draft-ietf-bfd-v4v6-1hop-11.txt
#define MinSourcePort (49142U)

//const uint16_t MaxSourcePort = 65535U;  // Per draft-ietf-bfd-v4v6-1hop-11.txt
#define MaxSourcePort (65535U)

//const uint8_t Version = 1;    // There has not yet been any official release
#define Version (1)

//const uint32_t BaseMinTxInterval = 1000000L;  // The base "slow" Tx interval.
#define BaseMinTxInterval (1000000L)

// State codes
typedef enum BFD_StateValue
{
  AdminDown = 0,
  Down      = 1,
  Init      = 2,
  Up        = 3,
}BFD_StateValue;

/*
const char* StateName(BFD_StateValue state);
*/

typedef enum BFD_DiagStateValue
{
  None = 0,
  ControlDetectExpired = 1,
  EchoFailed = 2,
  NeighborSessionDown = 3,
  ForwardingReset = 4,
  PathDown = 5,
  ConcatPathDown = 6,
  AdmDown = 7,
  ReverseConcatPathDown = 8,
  MaxDiagnostic = 31
}BFD_DiagStateValue;

/*
const char* DiagString(BFD_DiagStateValue diag);
const char* DiagShortString(BFD_DiagStateValue diag);
*/

// Authentication types
typedef enum BFD_AuthTypeValue
{
  none = 0,
  Password = 1,
  MD5 = 2,
  MeticulousMD5 = 3,
  SHA1 = 4,
  MeticulousSHA1 = 5,
}BFD_AuthTypeValue;


/**
 * The actual bfd packet structure.
 */
#pragma pack(push, 1)
typedef struct BfdPacketHeader
{
  uint8_t versAndDiag;      // version and diagnostic packed into 1 byte
  uint8_t flags;
  uint8_t detectMult;
  uint8_t length;           // Total packet length
  uint32_t myDisc;          // My Discriminator
  uint32_t yourDisc;        // Your Discriminator
  uint32_t txDesiredMinInt;
  uint32_t rxRequiredMinInt;
  uint32_t rxRequiredMinEchoInt;

  //manipulate bit fields
  /*
  inline uint8_t GetVersion() const { return ((versAndDiag & 0xE0) >> 5);}
  inline void SetVersion(uint8_t ver) { versAndDiag = ((ver & 0x07) << 5) | (versAndDiag & 0x1F);}
  inline bfd::Diag::Value GetDiag() const  { return bfd::Diag::Value(versAndDiag & 0x1F);}
  inline void SetDiag(bfd::Diag::Value diag) { versAndDiag = ((uint8_t)diag & 0x1F) | (versAndDiag & 0xE0);}
  inline bfd::State::Value GetState() const { return bfd::State::Value((flags >> 6) & 0x03);}
  inline void SetState(bfd::State::Value state) { flags = (((uint8_t)state & 0x03) << 6) | (flags & 0x3F);}
  inline bool GetPoll() const { return (flags & 0x20);}
  inline void SetPoll(bool val) { flags = val ? flags | 0x20 : flags & ~0x20;}
  inline bool GetFinal() const { return (flags & 0x10);}
  inline void SetFinal(bool val) { flags = val ? flags | 0x10 : flags & ~0x10;}
  inline bool GetControlPlaneIndependent() const { return (flags & 0x08);}
  inline void SetControlPlaneIndependent(bool val) { flags = val ? flags | 0x08 : flags & ~0x08;}
  inline bool GetAuth() const { return (flags & 0x04);}
  inline void SetAuth(bool val) { flags = val ? flags | 0x04 : flags & ~0x04;}
  inline bool GetDemand() const { return (flags & 0x02);}
  inline void SetDemand(bool val) { flags = val ? flags | 0x02 : flags & ~0x02;}
  inline bool GetMultipoint() const { return (flags & 0x01);}
  inline void SetMultipoint(bool val) { flags = val ? flags | 0x01 : flags & ~0x01;}
  */
}BfdPacketHeader;
#pragma pack(pop)

/**
 * Optional Authentication header.
 */
#pragma pack(push, 1)
typedef struct BFDAuthData
{
  uint8_t type;
  uint8_t len;
  uint8_t data[MaxAuthDataSize];  // enough room for the largest.

  /*
  inline BFD_GetAuthType() { return BFD_AuthTypeValue(type);}
  inline void BFD_SetAuthType(BFD_AuthTypeValue val) {type = (uint8_t)val;}
  */
}BFDAuthData;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct BfdPacket
{
  BfdPacketHeader header;
  BFDAuthData auth;
}BfdPacket;
#pragma pack(pop)







/********************************Interfaces***********************************/
#define MAX_BFD_SESSIONS (10)
typedef struct onvm_bfd_init_config {
        uint32_t bfd_identifier;
        uint8_t num_ports;
        uint8_t session_mode[MAX_BFD_SESSIONS];
}onvm_bfd_init_config_t;

#define BFD_SESSION_MODE_PASSIVE    (0)
#define BFD_SESSION_MODE_ACTIVE     (1)

/*
 * Interface to initialize the BFD.
 *
 * Input  : nfv_mgr identifier
 * Output : an error code
 *
 */
int
onvm_bfd_init(onvm_bfd_init_config_t *bfd_config);

/*
 * Interface to De-initialize the BFD.
 *
 * Input  : a pointer to the nf
 * Output : an error code
 *
 */
int
onvm_bfd_deinit(void);

/****************************Internal functions*******************************/


/*
 * Function starting a BFD.
 *
 * Input  :
 * Output : an error code
 *
 */
int
onvm_bfd_start(void);

/*
 * Function stopping a BFD.
 *
 * Input  : a pointer to the NF's informations
 * Output : an error code
 *
 */
int
onvm_bfd_stop(void);

#endif  // _ONVM_BFD_H_
