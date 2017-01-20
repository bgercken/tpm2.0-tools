
#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>

#include <sapi/tpm20.h>
#include "sample.h"
#include <tcti/tcti_socket.h>
#include "common.h"

int debugLevel = 0;

TPM_RC IsOwned()
{
	UINT32 rval = TPM_RC_SUCCESS;
	char manuID[5] = "    ";
	char *manuIDPtr = &manuID[0];
	TPMI_YES_NO moreData;
	TPMS_CAPABILITY_DATA capabilityData;

	rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_PERMANENT, 1, &moreData, &capabilityData, 0);
	if(rval != TPM_RC_SUCCESS)
	{
		printf("Failed to get TPM_PT_PERMANENT, error code: 0x%0x\n", rval);
		return rval;
	}

	/* 1 if HierarchyChangeAuth (ownership) has been taken since last tpm2_clear, 0 if unowned */
	printf("%d", capabilityData.data.tpmProperties.tpmProperty[0].value & TPMA_PERMANENT_OWNERAUTHSET);

	return rval;

}

int main()
{
	UINT32 rval;
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    prepareTest(hostName, port, debugLevel);
	rval = IsOwned();
	if(rval != TPM_RC_SUCCESS)
	{
		printf("IsOwned failed. \n");
		return -1;
	}

    finishTest();
	return 0;
}
