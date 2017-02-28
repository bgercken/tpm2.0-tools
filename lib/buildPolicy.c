
#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "tpm_session.h"
#include "tpm_hash.h"
#include "string-bytes.h"
	

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
    (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define INIT_SIMPLE_TPM2B_SIZE( type ) (type).t.size = sizeof( type ) - 2;

void zero_pcr_selection(TPML_PCR_SELECTION *pcrsIn, TPMI_ALG_HASH nameAlg)
{
	memset(&pcrsIn->pcrSelections[0], 0, sizeof(TPMS_PCR_SELECTION));
	pcrsIn->count = 1; //This is misleading, but I believe it describes the size of pcrSelections
	pcrsIn->pcrSelections[0].hash = nameAlg;
	pcrsIn->pcrSelections[0].sizeofSelect = 3;
	pcrsIn->pcrSelections[0].pcrSelect[0] = 0;
	pcrsIn->pcrSelections[0].pcrSelect[1] = 0;
	pcrsIn->pcrSelections[0].pcrSelect[2] = 0;

}

int buildPcrPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest, pcr_struct **pcrList, UINT32 pcrCountIn, TPMI_ALG_HASH nameAlg)
{
	TPM_RC rval = TPM_RC_SUCCESS;
	TPM2B_DIGEST pcrDigest;
	TPML_DIGEST tmpPcrValues;
	TPM2B_MAX_BUFFER pcrValues[24];  //These need to be adjacent in mem for the hash_sequence call, we're only ever going read 24 max at a time
	TPML_PCR_SELECTION pcrs;
	TPML_PCR_SELECTION pcrsTmp;
	UINT32 pcrUpdateCounter;
	TPML_PCR_SELECTION pcrSelectionOut;
	
	int batch_index = 0;
	int pcrReadIndex = 0;
	int remaining = pcrCountIn;
	zero_pcr_selection(&pcrs, nameAlg);

	//Init the pcr selection we will use for the PCRPolicy call
	for(int i = 0; i < pcrCountIn; i++)
	{
		SET_PCR_SELECT_BIT( pcrs.pcrSelections[0], pcrList[i]->pcr );
	}

	//First cut at logic to handle a varying list of incoming PCRs. We are further limited by the max read size
    //of 8 digests at a time. Another constraint is that some of these PCRs have forward hashes, in which case
    //we skip the tpm read for that PCR and simply add the forward hash to the list of digests to sequence.
	while (1)
	{
		zero_pcr_selection(&pcrsTmp, nameAlg);
		for(int i = batch_index, j = 0; i < pcrCountIn && j < 8; i++,j++)
		{
			//forwardHash is empty, set the pcr select bit to get the value from the tpm
			if(!strcmp(pcrList[i]->forwardHash, ""))
			{
				SET_PCR_SELECT_BIT(pcrsTmp.pcrSelections[0], pcrList[i]->pcr);
				pcrReadIndex++; //inc number of pcrs we actually intend to read.
			} else {
				j--; //don't increment our batch counter if there's a forwardHash to process
			}
		}

		memset(&tmpPcrValues, 0, sizeof(TPML_DIGEST));
		rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrsTmp, &pcrUpdateCounter, &pcrSelectionOut, &tmpPcrValues, 0 );
		if( rval != TPM_RC_SUCCESS )
			return rval;

		//populate the hashes into our list of hashes
		for(int i = 0; i < tmpPcrValues.count; i++)
		{	
			pcrValues[i+batch_index].t.size = tmpPcrValues.digests[i].t.size; 
			memcpy(pcrValues[i+batch_index].t.buffer, tmpPcrValues.digests[i].t.buffer, tmpPcrValues.digests[i].t.size);
		}
		
		//subtract from our total the number read, if we're at 0 or less, we're done	
		remaining -= tmpPcrValues.count;
		if(remaining <= 0)
			break;
		batch_index+=8;
	}
	pcrReadIndex--;

	// If there are any provided forward hashes, add them into our TPM_MAX_BUFFER list for hashing into single digest.
	for(int i = 0; i < pcrCountIn; i++)
	{
		if(strcmp(pcrList[i]->forwardHash, ""))
		{
			memcpy(pcrValues[pcrReadIndex].t.buffer, pcrList[i]->forwardHash, sizeof(pcrList[i]->forwardHash));
			pcrReadIndex++;
		}
	}

	// Hash them together
	INIT_SIMPLE_TPM2B_SIZE( pcrDigest );
	rval = hash_sequence_ex( sysContext, policySession->authHash, pcrCountIn, &pcrValues[0], &pcrDigest );
	if( rval != TPM_RC_SUCCESS )
		return rval;

	rval = Tss2_Sys_PolicyPCR( sysContext, policySession->sessionHandle, 0, &pcrDigest, &pcrs, 0 );
	if( rval != TPM_RC_SUCCESS )
		return rval;

   return rval;
}

int buildPolicyExternal(TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, int trial, pcr_struct **pcrList, UINT32 pcrCount, TPM2B_DIGEST *policyDigestOut, TPMI_ALG_HASH nameAlg)
{
    TPM2B_DIGEST policyDigest;
    policyDigest.t.size = 0;
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = { {0}, };
    TPMT_SYM_DEF symmetric;
    TPM_RC rval;
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;

    // Start policy session.
    symmetric.algorithm = TPM_ALG_NULL;
	rval = tpm_session_start_auth_with_params(sysContext, policySession, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt,
		trial ? TPM_SE_TRIAL : TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256);  
    if( rval != TPM_RC_SUCCESS )
	{
		printf("BuildPolicyExternal, Unable to Start Auth Session, Error Code: 0x%x\n", rval);
        return rval;
	}

    // Send policy command.
    rval = buildPcrPolicy( sysContext, *policySession, &policyDigest, pcrList, pcrCount, nameAlg);
    if( rval != TPM_RC_SUCCESS )
	{
		printf("BuildPCRPolicy, Error Code: 0x%x\n", rval);
        return rval;
	}

    // Get policy hash.
    INIT_SIMPLE_TPM2B_SIZE( policyDigest );
    rval = Tss2_Sys_PolicyGetDigest( sysContext, (*policySession)->sessionHandle,
            0, &policyDigest, 0 );
    if( rval != TPM_RC_SUCCESS )
	{
		printf("PolicyGetDigest, Error Code: 0x%x\n", rval);
        return rval;
	}

   	if( trial )
	{ 
		// Need to flush the session here.
		rval = Tss2_Sys_FlushContext( sysContext, (*policySession)->sessionHandle );
		if( rval != TPM_RC_SUCCESS )
			return rval;

		// And remove the session from sessions table.
		rval = tpm_session_auth_end( *policySession );
		if( rval != TPM_RC_SUCCESS )
			return rval;
	} 

	memcpy(policyDigestOut->t.buffer, policyDigest.t.buffer, policyDigest.t.size);
	policyDigestOut->t.size = policyDigest.t.size;
	return rval;

}

