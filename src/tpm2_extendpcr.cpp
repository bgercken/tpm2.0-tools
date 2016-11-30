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

int findAlgorithm(TPMI_ALG_HASH algId)
{
    int i;
    for(i = 0; g_algs[i].alg != TPM_ALG_NULL; i++)
        if( g_algs[i].alg == algId )
            break;

    return i;
}

void updatePcrSelections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2)
{
    for(int i2 = 0; i2 < s2->count; i2++)
    {
        for(int i1 = 0; i1 < s1->count; i1++)
        {
            if(s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for(int j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
                s1->pcrSelections[i1].pcrSelect[j] &=
                    ~s2->pcrSelections[i2].pcrSelect[j];
        }
    }
}

bool emptyPcrSections(TPML_PCR_SELECTION *s)
{
    for(int i = 0; i < s->count; i++)
        for(int j = 0; j < s->pcrSelections[i].sizeofSelect; j++)
            if(s->pcrSelections[i].pcrSelect[j])
                return false;

    return true;
}

int readPcrValues()
{
    TPML_PCR_SELECTION pcrSelectionIn;
    TPML_PCR_SELECTION pcrSelectionOut;
    UINT32 pcrUpdateCounter;
    UINT32 rval;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcrSelectionIn, &g_pcrSelections, sizeof(pcrSelectionIn));

    //2. call pcr_read
    g_pcrs.count = 0;
    do
    {
        rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrSelectionIn,
                                  &pcrUpdateCounter, &pcrSelectionOut,
                                  &g_pcrs.pcrValues[g_pcrs.count], 0 );

        if(rval != TPM_RC_SUCCESS )
        {
            printf("read pcr failed. tpm error 0x%0x\n\n", rval);
            return -1;
        }

    //3. unmask pcrSelectionOut bits from pcrSelectionIn
        updatePcrSelections(&pcrSelectionIn, &pcrSelectionOut);

    //4. goto step 2 if pcrSelctionIn still has bits set
    } while(++g_pcrs.count < 24 && !emptyPcrSections(&pcrSelectionIn));

    if(g_pcrs.count >= 24 && !emptyPcrSections(&pcrSelectionIn))
    {
        printf("too much pcrs to get! try to split into multiple calls...\n\n");
        return -1;
    }

    return 0;
}

int showPcrValues()
{
    return 0;
}


void showHelp(const char *name)
{
    printf("\n%s  [options]\n"
            "-h, --help                Display command tool usage info;\n"
            "-v, --version             Display command tool version info;\n"
            "-s, --hash <hexHash>      The hashed data to extend the pcr with\n"
            "-c, --pcr <pcrId>     	   The id of the PCR to extend\n"
            "-g, --algorithim <hexAlg>     The algorithm id, optional\n"
            "-o, --output  <filename>      The file to hold the PCR values in binary format, optional\n"
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
            , name, DEFAULT_RESMGR_TPM_PORT, );
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

int main(int argc, char *argv[])
{
	char hash[SHA512_DIGEST_SIZE*2];
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;
	UINT32 pcr = -1;

    setbuf(stdout, NULL);
    setvbuf (stdout, NULL, _IONBF, BUFSIZ);

    int opt = -1;
    const char *optstring = "hvg:p:d:o:L:s";
    static struct option long_options[] = {
        {"help",0,NULL,'h'},
        {"version",0,NULL,'v'},
        {"hash",0,NULL,'s'},
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
        o_flag = 0,
        L_flag = 0,
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
		case 's':
			//Read string representation of sha hash
			//Verify validity of hash (hex digits only)
			//hash comes in as string ie sha512sum = 3b12a25123af..., digest size is only 64 but string has 128 bits
			//encode string to byte representation, so 2 chars = 1 byte of digest.
			safeStrNCpy(hash, optarg, sizeof(hash));
			if ( verifyHash(hash) );
			{
				printf("Failed to read provided hash data.\n");
				returnVal = -5;
			}
			break;
		case 'c':
			if ( getPcrId(optarg, &pcr) )
			{
				printf("Invalid pcr value.\n");
				returnVal = -6;
			}
			break;
        case ':':
            returnVal = -7;
            break;
        case '?':
            returnVal = -8;
            break;
        }
        if(returnVal)
            break;
    };

    if(returnVal != 0)
        return returnVal;
    flagCnt = h_flag + v_flag + g_flag + L_flag + s_flag;

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

    prepareTest(hostName, port, debugLevel);

    if(returnVal == 0)
    {
        if(s_flag)
            showBanks();
        else if(g_flag)
            returnVal = showAlgPcrValues(algorithmId);
        else if(L_flag)
            returnVal = showSelectedPcrValues();
        else
            returnVal = showAllPcrValues();
    }

    finishTest();

    if(fp)
        fclose(fp);
    if(returnVal)
        return -9;

    return 0;
}
