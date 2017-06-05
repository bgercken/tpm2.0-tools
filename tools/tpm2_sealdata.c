
//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// Copyright (c) 2017, Assured Information Security
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
#include <tcti/tcti_socket.h>
#include "pcr.h"
#include "options.h"
#include "log.h"
#include "tpm_session.h"
#include "string-bytes.h"
#include "files.h"
#include "shared.h"

TPM_HANDLE handle2048rsa;

int seal(TSS2_SYS_CONTEXT *sapi_context, TPM2B_SENSITIVE_CREATE *inSensitive, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, char *outputPublicFilepath, 
         char *outputPrivateFilepath, int o_flag, int O_flag, int I_flag, int b_flag, UINT32 objectAttributes, pcr_struct **pcrList, 
         INT32 pcrCount)
{
    UINT32 rval;
    SESSION *policySession1, *policySession256;
    TPM2B_PUBLIC inPublic;
    TPM2B_DIGEST policyDigest1, policyDigest256;

    //Build a trial policy gated by the provided PCR
    rval = build_policy_external(sapi_context, &policySession1, true, pcrList, pcrCount, &policyDigest1, TPM_ALG_SHA1);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("build_policy failed, ec: 0x%x\n", rval);
        return rval;
    }

    rval = build_policy_external(sapi_context, &policySession256, true, pcrList, pcrCount, &policyDigest256, TPM_ALG_SHA256);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("build_policy failed, ec: 0x%x\n", rval);
        return rval;
    }
    inPublic.t.publicArea.authPolicy.t.size = 0;
    //inPublic.t.publicArea.authPolicy.t.size = policyDigest.t.size;
    //memcpy(inPublic.t.publicArea.authPolicy.t.buffer, policyDigest.t.buffer, policyDigest.t.size);

    //Seal the provided data
    rval = create(sapi_context, handle2048rsa, &inPublic, inSensitive, type, nameAlg, outputPublicFilepath, outputPrivateFilepath, o_flag, O_flag, I_flag, b_flag, objectAttributes, policySession1, policySession256);
    if(rval != TPM_RC_SUCCESS)
    {
        printf("create() failed, ec: 0x%x\n", rval);
        Tss2_Sys_FlushContext( sapi_context, policySession1->sessionHandle);
        Tss2_Sys_FlushContext( sapi_context, policySession256->sessionHandle);

        if(tpm_session_auth_end(policySession1) != TPM_RC_SUCCESS)
            printf("tpm2_session_auth_end failed\n");
        if(tpm_session_auth_end(policySession256) != TPM_RC_SUCCESS)
            printf("tpm2_session_auth_end failed\n");
        return rval;
    }

	Tss2_Sys_FlushContext( sapi_context, policySession1->sessionHandle);
	Tss2_Sys_FlushContext( sapi_context, policySession256->sessionHandle);

	if(tpm_session_auth_end(policySession1) != TPM_RC_SUCCESS)
		printf("tpm2_session_auth_end failed\n");
	if(tpm_session_auth_end(policySession256) != TPM_RC_SUCCESS)
		printf("tpm2_session_auth_end failed\n");
    return rval;

}

int
execute_tool(int                 argc,
             char*                 argv[],
             char*                 envp[],
             common_opts_t        *opts,
             TSS2_SYS_CONTEXT     *sapi_context)
{
    (void) envp;
    (void) opts;

    TPM2B_SENSITIVE_CREATE  inSensitive;
    inSensitive.t.sensitive.data.t.size = 0;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    UINT32 objectAttributes = 0;
    char opuFilePath[PATH_MAX] = {0};
    char oprFilePath[PATH_MAX] = {0};

    UINT32 pcr = -1;
    INT32 pcrCount = 0;
    pcr_struct* pcrList[24];
    BYTE forwardHash[32] = {0};

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "H:K:g:G:I:o:O:b:r:";
    static struct option long_options[] = {
      {"pwdk",1,NULL,'K'},
      {"halg",1,NULL,'g'},
      {"kalg",1,NULL,'G'},
      {"objectAttributes",1,NULL,'b'},
      {"pcr",1,NULL,'r'},
      {"inFile",1,NULL,'I'},
      {"opu",1,NULL,'o'},
      {"opr",1,NULL,'O'},
      {"handle",1,NULL,'H'},
      {0,0,0,0}
    };

    int returnVal = 0;
    int flagCnt = 0;
    int H_flag = 0,
        K_flag = 0,
        g_flag = 0,
        G_flag = 0,
        I_flag = 0,
        o_flag = 0,
        b_flag = 0,
        r_flag = 0,
        O_flag = 0;

    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'K':
            inSensitive.t.sensitive.userAuth.t.size = sizeof(inSensitive.t.sensitive.userAuth.t) - 2;
            if(str2ByteStructure(optarg,&inSensitive.t.sensitive.userAuth.t.size, inSensitive.t.sensitive.userAuth.t.buffer) != 0)
            {
                returnVal = -2;
                break;
            }
            K_flag = 1;
            break;
        case 'g':
            if(!string_bytes_get_uint16(optarg,&nameAlg))
            {
                showArgError(optarg, argv[0]);
                returnVal = -3;
                break;
            }
            printf("nameAlg = 0x%4.4x\n", nameAlg);
            g_flag = 1;
            break;
        case 'G':
            if(!string_bytes_get_uint16(optarg,&type))
            {
                showArgError(optarg, argv[0]);
                returnVal = -4;
                break;
            }
            printf("type = 0x%4.4x\n", type);
            G_flag = 1;
            break;
        case 'b':
            if(!string_bytes_get_uint32(optarg,&objectAttributes))
            {
                showArgError(optarg, argv[0]);
                returnVal = -5;
                break;
            }
            b_flag = 1;
            break;
        case 'I':
            inSensitive.t.sensitive.data.t.size = sizeof(inSensitive.t.sensitive.data) - 2;
            if(!files_load_bytes_from_file(optarg, inSensitive.t.sensitive.data.t.buffer, &inSensitive.t.sensitive.data.t.size))
            {
                returnVal = -6;
                break;
            }
            I_flag = 1;
            printf("inSensitive.t.sensitive.data.t.size = %d\n",inSensitive.t.sensitive.data.t.size);
            break;
        case 'o':
            snprintf(opuFilePath, sizeof(opuFilePath), "%s", optarg);
            if(files_does_file_exist(opuFilePath) != 0)
            {
                returnVal = -7;
                break;
            }
            o_flag = 1;
            break;
        case 'O':
            snprintf(oprFilePath, sizeof(oprFilePath), "%s", optarg);
            //Allow output file to be overwritten
            O_flag = 1;
            break;
        case 'H':
            if (!string_bytes_get_uint32(optarg, &handle2048rsa)) {
                printf(
                        "Could not convert object handle to a number, got: \"%s\"",
                        optarg);
                returnVal = -9;
            }
            H_flag = 1;
            break;
        case 'r':
            if ( pcr_parse_arg(optarg, &pcr, forwardHash) )
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
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        goto out;

    if(K_flag == 0)
        inSensitive.t.sensitive.userAuth.t.size = 0;

    flagCnt = g_flag + G_flag + I_flag + r_flag;
    if(flagCnt == 1)
    {
        showArgMismatch(argv[0]);
        returnVal = -16;
		goto out;
    }
    else if(flagCnt >= 4 && I_flag == 1 && g_flag == 1 && G_flag == 1 && r_flag == 1 && H_flag == 1)
    {
        if(returnVal == 0)
            returnVal = seal(sapi_context, &inSensitive, type, nameAlg, opuFilePath, oprFilePath, o_flag, O_flag, I_flag, b_flag, objectAttributes, pcrList, pcrCount);

        if(returnVal)
			goto out;

        //clean up pcr objects
        for(int i = 0; i < pcrCount; i++)
            free(pcrList[i]);
    }
    else
    {
        showArgMismatch(argv[0]);
        returnVal = -18;
		goto out;
    }

out:
	//clean up handle
	if(Tss2_Sys_FlushContext(sapi_context, handle2048rsa) != TPM_RC_SUCCESS)
            printf("FlushContext failed for handle, non-fatal\n");
    return returnVal;
}
