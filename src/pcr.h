#ifndef SRC_PCR_H_
#define SRC_PCR_H_

#include <sapi/tpm20.h>
int pcr_get_id(const char *arg, UINT32 *pcrId);
int pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels);
int pcr_parse_list(const char *str, int len, TPMS_PCR_SELECTION *pcrSel);
int pcr_parse_arg(const char *arg, UINT32 *pcrId, BYTE *forwardHash);

#endif /* SRC_PCR_H_ */
