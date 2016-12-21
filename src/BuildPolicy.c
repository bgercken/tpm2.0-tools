
#include <sapi/tpm20.h>
#include "sample.h"
#include <tcti/tcti_socket.h>
#include "common.h"

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
    (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define INIT_SIMPLE_TPM2B_SIZE( type ) (type).t.size = sizeof( type ) - 2;

TPM_RC BuildPcrPolicy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, TPM2B_DIGEST *policyDigest, UINT32 pcr)
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
	SET_PCR_SELECT_BIT( pcrs.pcrSelections[0], pcr );

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

TPM_RC BuildPolicyExternal(TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, int trial, UINT32 pcr, TPM2B_DIGEST *policyDigestOut)
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
    rval = StartAuthSessionWithParams( policySession, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt, 
        trial ? TPM_SE_TRIAL : TPM_SE_POLICY, &symmetric, TPM_ALG_SHA1 );
    if( rval != TPM_RC_SUCCESS )
	{
		printf("BuildPolicyExternal, Unable to Start Auth Session, Error Code: 0x%x\n", rval);
        return rval;
	}

    // Send policy command.
    rval = BuildPcrPolicy( sysContext, *policySession, &policyDigest, pcr );
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
		rval = EndAuthSession( *policySession );
		if( rval != TPM_RC_SUCCESS )
			return rval;
	} 

	memcpy(policyDigestOut->t.buffer, policyDigest.t.buffer, policyDigest.t.size);
	policyDigestOut->t.size = policyDigest.t.size;
	return rval;

}

