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

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "pcr.h"

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

int debugLevel = 0;
char outFilePath[PATH_MAX];

int doPcrExtendOp(BYTE * byteHash, UINT32 pcr, TPMI_ALG_HASH hashAlgIn)
{
	TPMS_AUTH_COMMAND sessionData;
	TSS2_SYS_CMD_AUTHS sessionsData;
	UINT16 i, digestSize;
	TPML_PCR_SELECTION pcrSelection;
	TPML_DIGEST pcrValues;
	TPML_DIGEST_VALUES digests;
	TPML_PCR_SELECTION pcrSelectionOut;
	TSS2_RC rval;

	TPMS_AUTH_COMMAND *sessionDataArray[1];

	sessionDataArray[0] = &sessionData;
	sessionsData.cmdAuths = &sessionDataArray[0];

	sessionData.sessionHandle = TPM_RS_PW;

	sessionData.nonce.t.size = 0;
	sessionData.hmac.t.size = 0;
	
	*( (UINT8 *)((void *)&sessionData.sessionAttributes ) ) = 0;
	
	digests.count = 1;
	digests.digests[0].hashAlg = hashAlgIn;
	digestSize = GetDigestSize( digests.digests[0].hashAlg );

	switch (hashAlgIn) {

		case TPM_ALG_SHA1:
			memcpy(digests.digests[0].digest.sha1, byteHash, SHA1_DIGEST_SIZE);
			break;
		case TPM_ALG_SHA256:
			memcpy(digests.digests[0].digest.sha256, byteHash, SHA256_DIGEST_SIZE);
			break;
		case TPM_ALG_SHA384:
			memcpy(digests.digests[0].digest.sha384, byteHash, SHA384_DIGEST_SIZE);
			break;
		case TPM_ALG_SHA512:
			memcpy(digests.digests[0].digest.sha512, byteHash, SHA512_DIGEST_SIZE);
			break;
		case TPM_ALG_SM3_256:
			memcpy(digests.digests[0].digest.sha1, byteHash, SM3_256_DIGEST_SIZE);
			break;
		default:
			printf("Invalid algorithm.  Exiting");
			return -1;
	}	

	pcrSelection.count = 1;
	pcrSelection.pcrSelections[0].hash = hashAlgIn;
	pcrSelection.pcrSelections[0].sizeofSelect = 3;

	CLEAR_PCR_SELECT_BITS(pcrSelection.pcrSelections[0]);	

	SET_PCR_SELECT_BIT(pcrSelection.pcrSelections[0], pcr); 

	sessionsData.cmdAuthsCount = 1;
	sessionsData.cmdAuths[0] = &sessionData;
	
	rval = Tss2_Sys_PCR_Extend( sysContext, pcr, &sessionsData, &digests, 0 );
	if( rval != TPM_RC_SUCCESS) {
		ErrorHandler(rval);
		printf("Failed to extend PCR: %d\n", pcr);
		return -2;
	}
	return 0;
}

int verifyHash(char *strhash)
{
	for(int i = 0; i < SHA512_DIGEST_SIZE*2; i++)
	{
		if(!isxdigit(strhash[i]) && strhash[i] != '\0')
			return -1;
	}
	return 0;
}

void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
            "-h, --help                Display command tool usage info;\n"
            "-v, --version             Display command tool version info;\n"
            "-s, --hash <hexHash>      The input hashed digest to extend the pcr with\n"
            "-c, --pcr <pcrId>     	   The id of the PCR to extend\n"
            "-g, --algorithim <hexAlg>     The algorithm id to use when extending pcr, examples:\n"
			"							       TPM_ALG_SHA1\n"
			"							       TPM_ALG_SHA256\n"
			"							       TPM_ALG_SHA384\n"
			"							       TPM_ALG_SHA512\n"
			"							       TPM_ALG_SM3_256\n"
            "-p, --port    <port number>   The Port number, default is %d, optional\n"
            "-d, --debugLevel <0|1|2|3>    The level of debug message, default is 0, optional\n"
                "\t0 (high level test results)\n"
                "\t1 (test app send/receive byte streams)\n"
                "\t2 (resource manager send/receive byte streams)\n"
                "\t3 (resource manager tables)\n"
            "\n\tExample:\n"
            "display usage:\n"
            "    %s -h\n"
            "display version:\n"
            "    %s -v\n"
            , name, DEFAULT_RESMGR_TPM_PORT );
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

/* 
   TODO:
   At the moment, only accepts digests as input values. Should implement
   functionality to accept files/streams of data, compute the digest of that
   data, and then extend the pcr.
 */
execute_tool(int 				argc, 
			 char* 				argv[],
			 char* 				envp[],
			 common_opts_t    	*opts,
             TSS2_SYS_CONTEXT 	*sapi_context)
{
	sysContext = sapi_context;	
	BYTE byteHash[SHA512_DIGEST_SIZE];
	UINT16 byteLength;
	char strHash[SHA512_DIGEST_SIZE*2] = {0};			//SHA512_DIGEST_SIZE*2 is the largest digest we'd encounter
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
	UINT32 pcr = -1;
	int ret = 0;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvg:p:d:s:c:";
    static struct option long_options[] = {
        {"help",0,NULL,'h'},
		{"version",0,NULL,'v'},
        {"algorithm",1,NULL,'g'},
        {"hash",1,NULL,'s'},
        {"pcr",1,NULL,'c'},
        {"port",1,NULL,'p'},
        {"debugLevel",1,NULL,'d'},
        {0,0,0,0}
    };

    TPMI_ALG_HASH algorithmId = 0;

    int returnVal = 0;
    int flagCnt = 0;
    int h_flag = 0,
        v_flag = 0,
        s_flag = 0,
        g_flag = 0;

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
		case 's':
			//safeStrNCpy(strHash, optarg, sizeof(strHash));
			//ret = verifyHash(strHash);
			//if ( ret != 0 )
			//{
			//	printf("Input digest is not in valid hexadecimal format.\n");
			//	returnVal = -5;
			//	break;
			//}
			printf("%s\n", optarg);
			memcpy(byteHash, optarg, sizeof(byteHash));
			printf("%s\n", byteHash);
			/*if ( hex2ByteStructure(strHash, &byteLength, byteHash) != 0)
			{
				printf("Failed to convert string representation of hash to byte array");
				returnVal = -6;
				break;
			}*/ 
			break;
		case 'c':
			if ( pcr_get_id(optarg, &pcr) )
			{
				printf("Invalid pcr value.\n");
				returnVal = -7;
			}
			break;
        case 'g':
            if(getSizeUint16Hex(optarg,&algorithmId) != 0)
            {
                showArgError(optarg, argv[0]);
                returnVal = -1;
                break;
            }
            g_flag = 1;
            break;
        case ':':
            returnVal = -8;
            break;
        case '?':
            returnVal = -9;
            break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag + g_flag + s_flag;

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

    prepareTest(hostName, port, debugLevel);

    if(returnVal == 0)
    {
		doPcrExtendOp(byteHash, pcr, algorithmId);
    }

    finishTest();

    if(returnVal)
        return -9;

    return 0;
}
