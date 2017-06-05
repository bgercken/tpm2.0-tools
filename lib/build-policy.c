#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include <stdio.h>
#include "tpm_session.h"
#include "tpm_hash.h"
#include "string-bytes.h"
#include "pcr.h"

#define INIT_SIMPLE_TPM2B_SIZE( type ) (type).t.size = sizeof( type ) - 2;

void zero_pcr_selection(TPML_PCR_SELECTION *pcrsIn, TPMI_ALG_HASH nameAlg)
{
    memset(&pcrsIn->pcrSelections[0], 0, sizeof(TPMS_PCR_SELECTION));
    pcrsIn->count = 1; //This describes the size of pcrSelections
    pcrsIn->pcrSelections[0].hash = nameAlg;
    pcrsIn->pcrSelections[0].sizeofSelect = 3;
    pcrsIn->pcrSelections[0].pcrSelect[0] = 0;
    pcrsIn->pcrSelections[0].pcrSelect[1] = 0;
    pcrsIn->pcrSelections[0].pcrSelect[2] = 0;

}

int build_pcr_policy( TSS2_SYS_CONTEXT *sysContext, SESSION *policySession, pcr_struct **pcrList, INT32 pcrCountIn, TPMI_ALG_HASH nameAlg)
{
    TPM2B_DIGEST pcrDigest;
    TPML_DIGEST tmpPcrValues;
    TPM2B_MAX_BUFFER pcrValues[24];
    TPML_PCR_SELECTION pcrs, pcrsTmp, pcrSelectionOut;
    UINT32 pcrUpdateCounter;

    TPM_RC rval = TPM_RC_SUCCESS;
    char empty[32] = {0};
    zero_pcr_selection(&pcrs, nameAlg);

    //Init the pcr selection we will use for the PCRPolicy call
    for(int i = 0; i < pcrCountIn; i++)
        SET_PCR_SELECT_BIT( pcrs.pcrSelections[0], pcrList[i]->pcr );

    for(int i = 0; i < pcrCountIn; i++)
    {
        //No forward hash provided, need to read this pcr
        if(!memcmp(pcrList[i]->forwardHash, empty, 32)) {
            zero_pcr_selection(&pcrsTmp, nameAlg);
            SET_PCR_SELECT_BIT(pcrsTmp.pcrSelections[0], pcrList[i]->pcr);
            memset(&tmpPcrValues, 0, sizeof(TPML_DIGEST));
            rval = Tss2_Sys_PCR_Read( sysContext, 0, &pcrsTmp, &pcrUpdateCounter, &pcrSelectionOut, &tmpPcrValues, 0 );
            if( rval != TPM_RC_SUCCESS )
                return rval;

            pcrValues[i].t.size = tmpPcrValues.digests[0].t.size;
            memcpy(pcrValues[i].t.buffer, tmpPcrValues.digests[0].t.buffer, tmpPcrValues.digests[0].t.size);
        } else {
            //Forward hash provided, copy into digest buffer
            memcpy(pcrValues[i].t.buffer, pcrList[i]->forwardHash, sizeof(pcrList[i]->forwardHash));
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

int build_policy_external(TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, int trial, pcr_struct **pcrList, INT32 pcrCount, TPM2B_DIGEST *policyDigestOut, TPMI_ALG_HASH nameAlg)
{
    TPM2B_DIGEST policyDigest;
    TPM2B_ENCRYPTED_SECRET  encryptedSalt = { {0}, };
    TPMT_SYM_DEF symmetric;
    TPM_RC rval;
    TPM2B_NONCE nonceCaller;

    nonceCaller.t.size = 0;
    policyDigest.t.size = 0;

    // Start policy session.
    symmetric.algorithm = TPM_ALG_NULL;
    rval = tpm_session_start_auth_with_params(sysContext, policySession, TPM_RH_NULL, 0, TPM_RH_NULL, 0, &nonceCaller, &encryptedSalt,
        trial ? TPM_SE_TRIAL : TPM_SE_POLICY, &symmetric, nameAlg);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("build_policy_external, Unable to Start Auth Session, Error Code: 0x%x\n", rval);
        return rval;
    }

    // Send policy command.
    rval = build_pcr_policy( sysContext, *policySession, pcrList, pcrCount, nameAlg);
    if( rval != TPM_RC_SUCCESS )
    {
        printf("build_pcr_policy, Error Code: 0x%x\n", rval);
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

    /*if( trial )
    {
        // Need to flush the session here.
        rval = Tss2_Sys_FlushContext( sysContext, (*policySession)->sessionHandle );
        if( rval != TPM_RC_SUCCESS )
            return rval;

        // And remove the session from sessions table.
        rval = tpm_session_auth_end( *policySession );
        if( rval != TPM_RC_SUCCESS )
            return rval;
    }*/

    memcpy(policyDigestOut->t.buffer, policyDigest.t.buffer, policyDigest.t.size);
    policyDigestOut->t.size = policyDigest.t.size;
    return rval;

}

