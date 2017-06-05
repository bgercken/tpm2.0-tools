//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>

#include <sapi/tpm20.h>

#include "files.h"
#include "main.h"
#include "options.h"
#include "string-bytes.h"
#include "shared.h"

TSS2_SYS_CONTEXT *sysContext;
TPMS_AUTH_COMMAND sessionData1;
TPMS_AUTH_COMMAND sessionData256;
bool hexPasswd = false;

int setAlg(TPMI_ALG_PUBLIC type,TPMI_ALG_HASH nameAlg,TPM2B_PUBLIC *inPublic, int I_flag)
{
    switch(nameAlg)
    {
    case TPM_ALG_SHA1:
    case TPM_ALG_SHA256:
    case TPM_ALG_SHA384:
    case TPM_ALG_SHA512:
    case TPM_ALG_SM3_256:
    case TPM_ALG_NULL:
        inPublic->t.publicArea.nameAlg = nameAlg;
        break;
    default:
        printf("nameAlg algrithm: 0x%0x not support !\n", nameAlg);
        return -1;
    }

    // First clear attributes bit field.
    *(UINT32 *)&(inPublic->t.publicArea.objectAttributes) = 0;
    inPublic->t.publicArea.objectAttributes.restricted = 0;
    inPublic->t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic->t.publicArea.objectAttributes.decrypt = 1;
    inPublic->t.publicArea.objectAttributes.sign = 1;
    inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic->t.publicArea.objectAttributes.fixedParent = 1;
    inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 1;

    inPublic->t.publicArea.type = type;
    switch(type)
    {
    case TPM_ALG_RSA:
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->t.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic->t.publicArea.unique.rsa.t.size = 0;
        break;

    case TPM_ALG_KEYEDHASH:
        inPublic->t.publicArea.unique.keyedHash.t.size = 0;
        inPublic->t.publicArea.objectAttributes.decrypt = 0;
        if (I_flag)
        {
            // sealing
            inPublic->t.publicArea.objectAttributes.sign = 0;
            inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 0;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
        }
        else
        {
            // hmac
            inPublic->t.publicArea.objectAttributes.sign = 1;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
            inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = nameAlg;  //for tpm2_hmac multi alg
        }
        break;

    case TPM_ALG_ECC:
        inPublic->t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        inPublic->t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.unique.ecc.x.t.size = 0;
        inPublic->t.publicArea.unique.ecc.y.t.size = 0;
        break;

    case TPM_ALG_SYMCIPHER:
        inPublic->t.publicArea.parameters.symDetail.sym.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.symDetail.sym.keyBits.sym = 128;
        inPublic->t.publicArea.parameters.symDetail.sym.mode.sym = TPM_ALG_CFB;
        inPublic->t.publicArea.unique.sym.t.size = 0;
        break;

    default:
        printf("type algrithm: 0x%0x not support !\n",type);
        return -2;
    }
    return 0;
}

int create(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT parentHandle, TPM2B_PUBLIC *inPublic, TPM2B_SENSITIVE_CREATE *inSensitive, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, const char *opuFilePath, const char *oprFilePath, int o_flag, int O_flag, int I_flag, int A_flag, UINT32 objectAttributes, SESSION* policySession1, SESSION* policySession256)
{
    TPM_RC rval;
    TPMS_AUTH_RESPONSE sessionDataOut1;
    TPMS_AUTH_RESPONSE sessionDataOut256;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[2];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[2];

    TPM2B_DATA              outsideInfo = { { 0, } };
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_PUBLIC            outPublic = { { 0, } };
    TPM2B_PRIVATE           outPrivate = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

    TPM2B_CREATION_DATA     creationData = { { 0, } };
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = { 0, };

    if(sapi_context)
        sysContext = sapi_context;

    sessionDataArray[0] = &sessionData1;
    sessionDataOutArray[0] = &sessionDataOut1;

    sessionDataArray[1] = &sessionData256;
    sessionDataOutArray[1] = &sessionDataOut256;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 2;
    sessionsData.cmdAuthsCount = 2;

    sessionData1.sessionHandle = TPM_RS_PW;
    sessionData1.nonce.t.size = 0;
    *((UINT8 *)((void *)&sessionData1.sessionAttributes)) = 0;

    sessionData256.sessionHandle = TPM_RS_PW;
    sessionData256.nonce.t.size = 0;
    *((UINT8 *)((void *)&sessionData256.sessionAttributes)) = 0;

    //Set hmac size to 0, sealing using adminWithPolicy
    sessionData1.hmac.t.size = 0;
    sessionData256.hmac.t.size = 0;
    if (sessionData1.hmac.t.size > 0 && hexPasswd)
    {
        sessionData1.hmac.t.size = sizeof(sessionData1.hmac) - 2;
        if (hex2ByteStructure((char *)sessionData1.hmac.t.buffer,
                              &sessionData1.hmac.t.size,
                              sessionData1.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for parent Passwd.\n");
            return -1;
        }
    }

    if (inSensitive->t.sensitive.userAuth.t.size > 0 && hexPasswd)
    {
        inSensitive->t.sensitive.userAuth.t.size = sizeof(inSensitive->t.sensitive.userAuth) - 2;
        if (hex2ByteStructure((char *)inSensitive->t.sensitive.userAuth.t.buffer,
                              &inSensitive->t.sensitive.userAuth.t.size,
                              inSensitive->t.sensitive.userAuth.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for object Passwd.\n");
            return -1;
        }
    }
    inSensitive->t.size = inSensitive->t.sensitive.userAuth.b.size + 2;

    if(setAlg(type, nameAlg, inPublic, I_flag))
        return -1;

    if(A_flag == 1)
        inPublic->t.publicArea.objectAttributes.val = objectAttributes;
    printf("ObjectAttribute: 0x%08X\n",inPublic->t.publicArea.objectAttributes.val);

    creationPCR.count = 0;

    sessionData1.sessionHandle = policySession1->sessionHandle;
    sessionData256.sessionHandle = policySession256->sessionHandle;

    rval = Tss2_Sys_Create(sysContext, parentHandle, &sessionsData, inSensitive, inPublic,
            &outsideInfo, &creationPCR, &outPrivate,&outPublic,&creationData, &creationHash,
            &creationTicket, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nCreate Object Failed ! ErrorCode: 0x%0x\n\n",rval);
        return -2;
    }
    printf("\nCreate Object Succeed !\n");

    /*
     * TODO These public and private serializations are not safe since its outputting size as well.
     */
    if(o_flag == 1)
    {
        if(!files_save_bytes_to_file(opuFilePath, (UINT8 *)&outPublic, sizeof(outPublic)))
            return -3;
    }
    if(O_flag == 1)
    {
        if(!files_save_bytes_to_file(oprFilePath, (UINT8 *)&outPrivate, sizeof(outPrivate)))
            return -4;
    }

    return 0;
}
