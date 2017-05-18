#ifndef SRC_SHARED_H
#define SRC_SHARED_H

#include <sapi/tpm20.h>

#include "tpm_session.h"
#include "pcr.h"

int setAlg(TPMI_ALG_PUBLIC type,TPMI_ALG_HASH nameAlg,TPM2B_PUBLIC *inPublic, int I_flag);

int create(TSS2_SYS_CONTEXT *sysContext, TPMI_DH_OBJECT parentHandle, TPM2B_PUBLIC *inPublic, TPM2B_SENSITIVE_CREATE *inSensitive, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, const char *opuFilePath, const char *oprFilePath, int o_flag, int O_flag, int I_flag, int A_flag, UINT32 objectAttributes);

int build_policy_external(TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, int trial, pcr_struct **pcrList, INT32 pcrCount, TPM2B_DIGEST *policyDigestOut, TPMI_ALG_HASH nameAlg);

#endif /* SRC_SHARED_H */
