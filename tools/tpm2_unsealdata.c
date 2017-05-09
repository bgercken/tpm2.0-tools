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
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "pcr.h"
#include "log.h"
#include "options.h"
#include "tpm_session.h"
#include "string-bytes.h"

TPMS_AUTH_COMMAND sessionData;
int hexPasswd = false;
TPM_HANDLE handle2048rsa;
TPM_HANDLE primaryHandle;
int debugLevel = 0;

int setAlg(TPMI_ALG_PUBLIC type,TPMI_ALG_HASH nameAlg,TPM2B_PUBLIC *inPublic)
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
    inPublic->t.publicArea.objectAttributes.restricted = 1;
    inPublic->t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic->t.publicArea.objectAttributes.decrypt = 1;
    inPublic->t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic->t.publicArea.objectAttributes.fixedParent = 1;
    inPublic->t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic->t.publicArea.authPolicy.t.size = 0;

    inPublic->t.publicArea.type = type;
    switch(type)
    {
    case TPM_ALG_RSA:
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        inPublic->t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        inPublic->t.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic->t.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic->t.publicArea.unique.rsa.t.size = 0;
        break;

    case TPM_ALG_KEYEDHASH:
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM_ALG_SHA256;
        inPublic->t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM_ALG_KDF1_SP800_108;
        inPublic->t.publicArea.unique.keyedHash.t.size = 0;
        break;

    case TPM_ALG_ECC:
        inPublic->t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
        inPublic->t.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        inPublic->t.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM_ALG_CFB;
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

int createPrimary(TSS2_SYS_CONTEXT *sapi_context, TPMI_RH_HIERARCHY hierarchy, TPM2B_PUBLIC *inPublic, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, int P_flag)
{
	TPM_RC rval;
	TPMS_AUTH_RESPONSE sessionDataOut;
	TSS2_SYS_CMD_AUTHS sessionsData;
	TSS2_SYS_RSP_AUTHS sessionsDataOut;
	TPMS_AUTH_COMMAND *sessionDataArray[1];
	TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

	TPM2B_DATA              outsideInfo = { { 0, } };
	TPML_PCR_SELECTION      creationPCR;
	TPM2B_NAME              name = { { sizeof(TPM2B_NAME)-2, } };
	TPM2B_PUBLIC            outPublic = { { 0, } };
	TPM2B_CREATION_DATA     creationData = { { 0, } };
	TPM2B_DIGEST            creationHash = { { sizeof(TPM2B_DIGEST)-2, } };
	TPMT_TK_CREATION        creationTicket = { 0, };
	TPM2B_SENSITIVE_CREATE inSensitive;

	sessionDataArray[0] = &sessionData;
	sessionDataOutArray[0] = &sessionDataOut;

	sessionsDataOut.rspAuths = &sessionDataOutArray[0];
	sessionsData.cmdAuths = &sessionDataArray[0];

	sessionsData.cmdAuthsCount = 1;
	sessionsDataOut.rspAuthsCount = 1;

	sessionData.sessionHandle = TPM_RS_PW;
	sessionData.nonce.t.size = 0;

	if(P_flag == 0)
		sessionData.hmac.t.size = 0;
	
	*((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;
	
	if (sessionData.hmac.t.size > 0 && hexPasswd)
	{
		sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
		if (hex2ByteStructure((char *)sessionData.hmac.t.buffer,
							  &sessionData.hmac.t.size,
							  sessionData.hmac.t.buffer) != 0)
		{
			printf( "Failed to convert Hex format password for hierarchy Passwd.\n");
			return -1;
		}
	}

	//remove this line if uncommenting above block
	inSensitive.t.sensitive.userAuth.t.size = 0;

	inSensitive.t.sensitive.data.t.size = 0;
	inSensitive.t.size = inSensitive.t.sensitive.userAuth.b.size + 2;

    if(setAlg(type, nameAlg, inPublic))
        return -1;

    creationPCR.count = 0;

    rval = Tss2_Sys_CreatePrimary(sapi_context, hierarchy, &sessionsData, &inSensitive, inPublic, &outsideInfo, &creationPCR, &primaryHandle, &outPublic, &creationData, &creationHash, &creationTicket, &name, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nCreatePrimary Failed ! ErrorCode: 0x%0x\n\n",rval);
        return -2;
    }

	return 0;
}


UINT32 load(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT itemHandle, TPM2B_PUBLIC *inPublic, TPM2B_PRIVATE *inPrivate, int A_flag, int P_flag) 
{
    UINT32 rval;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_NAME nameExt = { { sizeof(TPM2B_NAME)-2, } };

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;
	sessionData.sessionAttributes.continueSession = 1;
    if(P_flag == 0)
        sessionData.hmac.t.size = 0;
    if (sessionData.hmac.t.size > 0 && hexPasswd)
    {
        sessionData.hmac.t.size = sizeof(sessionData.hmac) - 2;
        if (hex2ByteStructure((char *)sessionData.hmac.t.buffer,
                              &sessionData.hmac.t.size,
                              sessionData.hmac.t.buffer) != 0)
        {
            printf( "Failed to convert Hex format password for item Passwd.\n");
            return -1;
        }
    }

	//Use the handle we just created from CreatePrimary
	//Otherwise, use the provided handle
	if(A_flag)
    	rval = Tss2_Sys_Load(sapi_context, primaryHandle, &sessionsData, inPrivate , inPublic, &handle2048rsa, &nameExt, &sessionsDataOut);
	else
	    rval = Tss2_Sys_Load(sapi_context, itemHandle, &sessionsData, inPrivate , inPublic, &handle2048rsa, &nameExt, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("\nLoad Object Failed ! ErrorCode: 0x%0x\n\n",rval);
        return rval;
    }

	return 0;

}

UINT32 unseal(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT itemHandle, const char *outFileName, int P_flag, TPM2B_PUBLIC *inPublic, TPM2B_PRIVATE *inPrivate, TPMI_ALG_HASH nameAlg, 
				pcr_struct **pcrList, UINT32 pcrCount, TPMI_RH_HIERARCHY hierarchy, int A_flag)
{
    UINT32 rval;
	SESSION *policySession;
	TPM2B_DIGEST policyDigest; //unused for now here but buildPolicyExternal needs to return the policy for sealdata.
	TPM2B_PUBLIC tempPublic;

	rval = buildPolicyExternal(sapi_context, &policySession, false, pcrList, pcrCount, &policyDigest, nameAlg);  //Build real policy, don't write to file
	if(rval != TPM_RC_SUCCESS)
	{
		printf("buildPolicy() failed, ec: 0x%x\n", rval);
		if(tpm_session_auth_end(policySession) != TPM_RC_SUCCESS) 
			printf("tpm2_session_auth_end failed: ec: 0x%x\n", rval);
		return rval;
	}

	//Create the parent context
	/*if(A_flag)
	{
		rval = CreatePrimary(hierarchy, &tempPublic, TPM_ALG_RSA, nameAlg, P_flag); 
		if(rval != TPM_RC_SUCCESS)
		{
			printf("CreatePrimary failed, errorcode: 0x%x\n", rval);
			return rval;
		}
	}
	*/

	rval = load(sapi_context, itemHandle, inPublic, inPrivate, A_flag, P_flag);
	if(rval != TPM_RC_SUCCESS)
	{
		printf("load() failed, ec: 0x%x\n", rval);
		if(tpm_session_auth_end(policySession) != TPM_RC_SUCCESS) 
			printf("tpm2_session_auth_end failed\n");
		return rval;
	}

    TPMS_AUTH_RESPONSE sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];

    TPM2B_SENSITIVE_DATA outData = {{sizeof(TPM2B_SENSITIVE_DATA)-2, }};

    sessionDataArray[0] = &sessionData;
    sessionDataOutArray[0] = &sessionDataOut;

    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];

    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

    sessionData.sessionHandle = policySession->sessionHandle;
    rval = Tss2_Sys_Unseal(sapi_context, handle2048rsa, &sessionsData, &outData, &sessionsDataOut);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("unseal() failed. ec: 0x%x\n", rval);
		if(tpm_session_auth_end(policySession) != TPM_RC_SUCCESS) 
			printf("tpm2_session_auth_end failed\n");
        return rval;
    }

	//Write data directly to stdout, to be consumed by the caller
	fwrite(outData.t.buffer, 1, outData.t.size, stdout);

    /*if(saveDataToFile(outFileName, (UINT8 *)outData.t.buffer, outData.t.size))
    {
        printf("Failed to save unsealed data into %s\n", outFileName);
        return -2;
    }*/

	rval = tpm_session_auth_end(policySession);
	if(rval != TPM_RC_SUCCESS)
	{
		printf("tpm2_session_auth_end failed: ec: 0x%x\n", rval);
		return -4;
	}

    return 0;
}

int 
execute_tool(int 			  argc, 
			 char			  *argv[], 
             char             *envp[],
             common_opts_t    *opts,
             TSS2_SYS_CONTEXT *sapi_context)
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
	
	TPMI_ALG_HASH nameAlg;
    TPMI_DH_OBJECT itemHandle;
    TPM2B_PUBLIC  inPublic;
    TPM2B_PRIVATE inPrivate;
    char outFilePath[PATH_MAX] = {0};
    char *contextItemFile = NULL;
    char *contextLoadFile = NULL;
    TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL;
	UINT16 size;
	UINT32 pcr = -1;
	UINT32 pcrCount = 0;
	pcr_struct * pcrList[24];
	BYTE forwardHash[32] = {0};

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    memset(&inPublic,0,sizeof(TPM2B_PUBLIC));
    memset(&inPrivate,0,sizeof(TPM2B_SENSITIVE));
    int opt = -1;
    const char *optstring = "H:P:o:c:r:u:C:g:n:A:X";
    static struct option long_options[] = {
      {"item",1,NULL,'H'},
      {"pwdi",1,NULL,'P'},
      {"auth",1,NULL,'A'},
      {"outfile",1,NULL,'o'},
      {"pubfile",1,NULL,'u'},
      {"privfile",1,NULL,'n'},
      {"itemContext",1,NULL,'c'},
      {"halg",1,NULL,'g'},
      {"pcr",1,NULL,'r'},
      {"loadContext",1,NULL,'C'},
      {"passwdInHex",0,NULL,'X'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int H_flag = 0,
        P_flag = 0,
        c_flag = 0,
        C_flag = 0,
        u_flag = 0,
        r_flag = 0,
        g_flag = 0,
        n_flag = 0,
        A_flag = 0,
        o_flag = 0;

    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
		case 'A':
            if(strcmp(optarg,"o") == 0 || strcmp(optarg,"O") == 0)
                hierarchy = TPM_RH_OWNER;
            else if(strcmp(optarg,"p") == 0 || strcmp(optarg,"P") == 0)
                hierarchy = TPM_RH_PLATFORM;
            else if(strcmp(optarg,"e") == 0 || strcmp(optarg,"E") == 0)
                hierarchy = TPM_RH_ENDORSEMENT;
            else if(strcmp(optarg,"n") == 0 || strcmp(optarg,"N") == 0)
                hierarchy = TPM_RH_NULL;
            else
            {
                returnVal = -1;
                break;
            }
            A_flag = 1;
            break;
        case 'H':
            if(getSizeUint32Hex(optarg, &itemHandle) != 0)
            {
                returnVal = -2;
                break;
            }
            H_flag = 1;
            break;
        case 'P':
            sessionData.hmac.t.size = sizeof(sessionData.hmac.t) - 2;
            if(str2ByteStructure(optarg,&sessionData.hmac.t.size,sessionData.hmac.t.buffer) != 0)
            {
                returnVal = -3;
                break;
            }
            P_flag = 1;
            break;
        case 'o':
            snprintf(outFilePath, sizeof(outFilePath), "%s", optarg);
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -4;
                break;
            }
            o_flag = 1;
            break;
        case 'c':
            contextItemFile = optarg;
            if(contextItemFile == NULL || contextItemFile[0] == '\0')
            {
                returnVal = -7;
                break;
            }
            c_flag = 1;
            break;
        case 'C':
            contextLoadFile = optarg;
            if(contextLoadFile == NULL || contextLoadFile[0] == '\0')
            {
                returnVal = -8;
                break;
            }
            C_flag = 1;
			break;
        case 'u':
            size = sizeof(inPublic);
            if(loadDataFromFile(optarg, (UINT8 *)&inPublic, &size) != 0)
            {
                returnVal = -9;
                break;
            }
            u_flag = 1;
            break;
        case 'n':
            size = sizeof(inPrivate);
            if(loadDataFromFile(optarg, (UINT8 *)&inPrivate, &size) != 0)
            {
                returnVal = -10;
                break;
            }
            n_flag = 1;
            break;
        case 'g':
            if(getSizeUint16Hex(optarg,&nameAlg) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -11;
                break;
            }
            g_flag = 1;
            break;
		case 'r':
			if ( pcr_parse_arg(optarg, &pcr, &forwardHash) )
			{
				printf("Invalid pcr value.\n");
				returnVal = -10;
				break;
			}
			r_flag = 1;
			pcr_struct *new_pcr = (pcr_struct *) malloc(sizeof(pcr_struct));
			new_pcr->pcr = pcr;
			memcpy(new_pcr->forwardHash, forwardHash, 32);
			memset(forwardHash, 0, 32);
			pcrList[pcrCount] = new_pcr;
			pcrCount++;
			break;
        case 'X':
            hexPasswd = true;
            break;
        case ':':
//              printf("Argument %c needs a value!\n",optopt);
            returnVal = -13;
            break;
        case '?':
//              printf("Unknown Argument: %c\n",optopt);
            returnVal = -13;
            break;
        //default:
        //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;

    flagCnt = H_flag + c_flag + n_flag + u_flag + g_flag + r_flag;
    if(flagCnt == 1)
    {
		showArgMismatch(argv[0]);
		return -14;
    }
    else if(flagCnt >= 4 && (H_flag == 1 || c_flag ==1 || A_flag == 1) && n_flag == 1 && u_flag == 1 && r_flag == 1)
    {
		
        //if(c_flag && (checkOutFile(contextItemFile) == -1))
        if(c_flag)
            returnVal = loadTpmContextFromFile(sapi_context, &itemHandle, contextItemFile );
        if (returnVal == 0)
            returnVal = unseal(sapi_context, itemHandle, outFilePath, P_flag, &inPublic, &inPrivate, nameAlg, pcrList, pcrCount, hierarchy, A_flag);
        if (returnVal == 0 && C_flag)
			returnVal = saveTpmContextToFile(sapi_context, handle2048rsa, contextLoadFile); 

		//clean up pcr objects
		for(int i = 0; i < pcrCount; i++)
			free(pcrList[i]);

		Tss2_Sys_FlushContext(sapi_context, itemHandle);

		//make sure handle2048 rsa is always cleaned
		Tss2_Sys_FlushContext(sapi_context, handle2048rsa);
        if(returnVal)
            return -15;
    }
    else
    {
        showArgMismatch(argv[0]);
        return -16;
    }

    return 0;
}
