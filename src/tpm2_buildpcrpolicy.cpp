//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
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

#ifdef _WIN32
#include "stdafx.h"
#else
#include <stdarg.h>
#endif

#ifndef UNICODE
#define UNICODE 1
#endif

#ifdef _WIN32
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define sprintf_s   snprintf
#define sscanf_s    sscanf
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sapi/tpm20.h>
#include "sample.h"
#include <tcti/tcti_socket.h>
#include "common.h"

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
    (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define CLEAR_PCR_SELECT_BITS( pcrSelection ) \
    (pcrSelection).pcrSelect[0] = 0; \
    (pcrSelection).pcrSelect[1] = 0; \
    (pcrSelection).pcrSelect[2] = 0;

#define SET_PCR_SELECT_SIZE( pcrSelection, size ) \
    (pcrSelection).sizeofSelect = size;

#define TEST_PCR_SELECT_BIT( pcrSelection, pcr ) \
    ((pcrSelection).pcrSelect[( (pcr)/8 )] & ( 1 << ( (pcr) % 8) ))

#define INIT_SIMPLE_TPM2B_SIZE( type ) (type).t.size = sizeof( type ) - 2;

int debugLevel = 0;
FILE *fp = NULL;
char outFilePath[PATH_MAX];
const struct {
    TPMI_ALG_HASH alg;
    const char *desc;
} g_algs [] =
{
    {TPM_ALG_SHA1, "TPM_ALG_SHA1"},
    {TPM_ALG_SHA256, "TPM_ALG_SHA256"},
    {TPM_ALG_SHA384, "TPM_ALG_SHA384"},
    {TPM_ALG_SHA512, "TPM_ALG_SHA512"},
    {TPM_ALG_SM3_256, "TPM_ALG_SM3_256"},
    {TPM_ALG_NULL, "TPM_ALG_UNKOWN"}
};

static struct {
    int count;
    TPMI_ALG_HASH alg[8];
} g_banks = {3, {TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,}};

TPML_PCR_SELECTION g_pcrSelections;

static struct {
    int count;
    TPML_DIGEST pcrValues[24];
} g_pcrs = {0,};



TPM_RC BuildPcrPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest )
{
    TPM_RC rval = TPM_RC_SUCCESS;
    TPM2B_DIGEST pcrDigest;
    TPML_DIGEST pcrValues;
    TPML_PCR_SELECTION pcrs;
    UINT32 pcrUpdateCounter;
    TPML_PCR_SELECTION pcrSelectionOut;

    pcrDigest.t.size = 0;

    pcrs.count = 1;
    pcrs.pcrSelections[0].hash = TPM_ALG_SHA1;
    pcrs.pcrSelections[0].sizeofSelect = 3;
    pcrs.pcrSelections[0].pcrSelect[0] = 0;
    pcrs.pcrSelections[0].pcrSelect[1] = 0;
    pcrs.pcrSelections[0].pcrSelect[2] = 0;
    SET_PCR_SELECT_BIT( pcrs.pcrSelections[0], 15 );

    //
    // Compute pcrDigest
    //
    // Read PCRs
    rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrs, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues, 0 );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    // Hash them together
    INIT_SIMPLE_TPM2B_SIZE( pcrDigest );
    rval = TpmHashSequence( policySession->authHash, pcrValues.count, &pcrValues.digests[0], &pcrDigest );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    rval = Tss2_Sys_PolicyPCR( sysContext, policySession->sessionHandle, 0, &pcrDigest, &pcrs, 0 );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    return rval;
}



TPM_RC BuildPolicy(bool trial)
{
    SESSION *policySession = 0;
    TPM2B_DIGEST policyDigest;
    policyDigest.t.size = 0;
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = { {0}, };
    TPMT_SYM_DEF symmetric;
    TPM_RC rval;
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;

    // Start policy session.
    symmetric.algorithm = TPM_ALG_NULL;
    rval = StartAuthSessionWithParams( &policySession, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, 
        trial ? TPM_SE_TRIAL : TPM_SE_POLICY, &symmetric, TPM_ALG_SHA1 );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    // Send policy command.
    rval = BuildPcrPolicy( sysContext, policySession, &policyDigest );
    if( rval != TPM_RC_SUCCESS )
        return rval;

    // Get policy hash.
    INIT_SIMPLE_TPM2B_SIZE( policyDigest );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, policySession->sessionHandle,
            0, &policyDigest, 0 );
    if( rval != TPM_RC_SUCCESS )
        return rval;

   	if( trial )
	{ 
		// Need to flush the session here.
		rval = Tss2_Sys_FlushContext( sysContext, policySession->sessionHandle );
		if( rval != TPM_RC_SUCCESS )
			return rval;

		// And remove the session from sessions table.
		rval = EndAuthSession( policySession );
		if( rval != TPM_RC_SUCCESS )
			return rval;
	} 

	printf("policyDigest.size = %d", policyDigest.t.size); 

    // Write PCR Policy in the file.
    if(fp != NULL &&
        fwrite(policyDigest.t.buffer, sizeof(BYTE), policyDigest.t.size, fp) != policyDigest.t.size)
    {
        printf("write to file %s failed!\n", outFilePath);
        return -1;
    }
    return rval;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
            "-h, --help                Display command tool usage info;\n"
            "-v, --version             Display command tool version info;\n"
            "-o, --output  <filename>      The file to hold the PCR values in binary format, optional\n"
            "-p, --port    <port number>   The Port number, default is %d, optional\n"
            "-L, --selList <hexAlg1:num1,...,numN+hexAlg2:num2_1,...,num2_M+...>\n"
            "                              The list of pcr banks and selected PCRs' ids\n"
            "                              (0~23) for each bank\n"
            "-d, --debugLevel <0|1|2|3>    The level of debug message, default is 0, optional\n"
                "\t0 (high level test results)\n"
                "\t1 (test app send/receive byte streams)\n"
                "\t2 (resource manager send/receive byte streams)\n"
                "\t3 (resource manager tables)\n"
			"-t, --trial"
            "\n\tExample:\n"
            "display usage:\n"
            "    %s -h\n"
            "display version:\n"
            "    %s -v\n"
            "display the PCR values with specified banks and store in a file:\n"
            "    %s -L 0x04:1,16 -o pcr_policy.bin\n"            
            , name, DEFAULT_RESMGR_TPM_PORT, name, name, name );
}

const char *findChar(const char *str, int len, char c)
{
    if(str == NULL || len <= 0)
        return NULL;

    for(int i = 0; i < len; i++)
    {
        if(str[i] == c)
            return &str[i];
    }

    return NULL;
}

int parsePCRList(const char *str, int len, TPMS_PCR_SELECTION *pcrSel)
{
    char buf[3];
    const char *strCurrent;
    int lenCurrent;
    UINT32 pcr;

    if(str == NULL || len == 0)
        return -1;

    pcrSel->sizeofSelect = 3;
    pcrSel->pcrSelect[0] = 0;
    pcrSel->pcrSelect[1] = 0;
    pcrSel->pcrSelect[2] = 0;

    do
    {
        strCurrent = str;
        str = findChar(strCurrent, len, ',');
        if(str)
        {
            lenCurrent = str - strCurrent;
            str++;
            len -= lenCurrent + 1;
        }
        else
        {
            lenCurrent = len;
            len = 0;
        }

        if(lenCurrent > sizeof(buf) - 1)
            return -1;

        safeStrNCpy(buf, strCurrent, lenCurrent + 1);

        if(getPcrId(buf, &pcr)!= 0)
            return -1;
		
		printf(" --- Pcr selected: %d", pcr);
		
        pcrSel->pcrSelect[pcr/8] |= (1 << (pcr % 8));
    } while(str);

    return 0;
}

int parsePCRSelection(const char *str, int len, TPMS_PCR_SELECTION *pcrSel)
{
    const char *strLeft;
    char buf[7];

    if(str == NULL || len == 0)
        return -1;

    strLeft = findChar(str, len, ':');

    if(strLeft == NULL)
        return -1;
    if(strLeft - str > sizeof(buf) - 1)
        return -1;

    safeStrNCpy(buf, str, strLeft - str + 1);
    if(getSizeUint16Hex(buf, &pcrSel->hash) != 0)
        return -1;

    strLeft++;

    if(strLeft - str >= len)
        return -1;

    if(parsePCRList(strLeft, str + len - strLeft, pcrSel))
        return -1;

    return 0;
}

int parsePCRSelections(const char *arg, TPML_PCR_SELECTION *pcrSels)
{
    const char *strLeft = arg;
    const char *strCurrent = arg;
    int lenCurrent = 0;

    if(arg == NULL || pcrSels == NULL)
        return -1;

    pcrSels->count = 0;

    do
    {
        strCurrent = strLeft;

        strLeft = findChar(strCurrent, strlen(strCurrent), '+');
        if(strLeft)
        {
            lenCurrent = strLeft - strCurrent;
            strLeft++;
        }
        else
            lenCurrent = strlen(strCurrent);

        if(parsePCRSelection(strCurrent, lenCurrent, &pcrSels->pcrSelections[pcrSels->count]))
            return -1;

        pcrSels->count++;
    } while(strLeft);

    if(pcrSels->count == 0)
        return -1;
    return 0;
}

int main(int argc, char *argv[])
{
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvtp:d:o:";
    static struct option long_options[] = {
        {"help",0,NULL,'h'},
        {"version",0,NULL,'v'},
        {"trial",0,NULL,'t'},
        {"output",1,NULL,'o'},
        {"port",1,NULL,'p'},
        {"debugLevel",1,NULL,'d'},
        {0,0,0,0}
    };

    TPMI_ALG_HASH algorithmId;

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        t_flag = 0,
        o_flag = 0;

    while((opt = getopt_long(argc,argv,optstring,long_options,NULL)) != -1)
    {
        switch(opt)
        {
        case 'h':
            h_flag = 1;
            break;
        case 'v':
            v_flag = 1;
            break;
        case 't':
            t_flag = 1;
            break;
        case 'o':
            safeStrNCpy(outFilePath, optarg, sizeof(outFilePath));
            if(checkOutFile(outFilePath) != 0)
            {
                returnVal = -2;
                break;
            }
            o_flag = 1;
            break;
        case 'p':
            if( getPort(optarg, &port) )
            {
                printf("Incorrect port number.\n");
                returnVal = -3;
            }
            break;
        case 'd':
            if( getDebugLevel(optarg, &debugLevel) )
            {
                printf("Incorrect debug level.\n");
                returnVal = -4;
            }
            break;
            //          case 0:
            //              break;
        case ':':
            //              printf("Argument %c needs a value!\n",optopt);
            returnVal = -5;
            break;
        case '?':
            //              printf("Unknown Argument: %c\n",optopt);
            returnVal = -6;
            break;
            //default:
            //  break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag;

    if(flagCnt > 1)
    {
        showArgMismatch(argv[0]);
        return -7;
    }

    if(h_flag)
    {
        showHelp(argv[0]);
        return 0;
    }
    else if(v_flag == 1)
    {
        showVersion(argv[0]);
        return 0;
    }

    if(o_flag)
    {
        fp = fopen(outFilePath,"w+");
        if(NULL == fp)
        {
            printf("OutFile: %s Can Not Be Created !\n",outFilePath);
            return -8;
        }
    }

    if((o_flag != 1))
    {
        showHelp(argv[0]);
        return -9;   
    }

    prepareTest(hostName, port, debugLevel);

    returnVal = BuildPolicy(t_flag);        

    finishTest();

    if(fp)
        fclose(fp);
    if(returnVal)
        return -9;

    return 0;
}
