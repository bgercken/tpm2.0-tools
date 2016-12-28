
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

UINT32 ChangeEndianDword( UINT32 p )
{
	return( ((const UINT32)(((p)& 0xFF) << 24))    | \
			((const UINT32)(((p)& 0xFF00) << 8))   | \
			((const UINT32)(((p)& 0xFF0000) >> 8)) | \
			((const UINT32)(((p)& 0xFF000000) >> 24)));

}

TPM_RC GetCapabilities()
{
	UINT32 rval = TPM_RC_SUCCESS;
	char manuID[5] = "    ";
	char *manuIDPtr = &manuID[0];
	TPMI_YES_NO moreData;
	TPMS_CAPABILITY_DATA capabilityData;

	printf("Get Capabilities: \n");

	rval = Tss2_Sys_GetCapability( sysContext, 0, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1, &moreData, &capabilityData, 0);
	if(rval != TPM_RC_SUCCESS)
	{
		printf("Failed to get manufacturer, error code: 0x%0x\n", rval);
		return rval;
	}

	*( (UINT32 *)manuIDPtr ) = ChangeEndianDword( capabilityData.data.tpmProperties.tpmProperty[0].value );
	printf("\t\tcount: %d, property: %x, manuId: %s\n",
			capabilityData.data.tpmProperties.count,
			capabilityData.data.tpmProperties.tpmProperty[0].property,
			manuID);
	
	//printf("PCRs implemented: %x\n", capabilityData.data.pcrProperties.pcrProperty[0].pcrSelect[0]);
	return rval;

}

int main()
{
	UINT32 rval;
    char hostName[200] = DEFAULT_HOSTNAME;
    int port = DEFAULT_RESMGR_TPM_PORT;

    prepareTest(hostName, port, debugLevel);
	rval = GetCapabilities();
	if(rval != TPM_RC_SUCCESS)
	{
		printf("GetCapabilities failed. \n");
		return -1;
	}

    finishTest();
	return 0;
}
