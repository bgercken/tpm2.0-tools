#ifndef SRC_PCR_H_
#define SRC_PCR_H_

#include <sapi/tpm20.h>

int pcr_get_id(const char *arg, UINT32 *pcrId);
int pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels);
int pcr_parse_list(const char *str, int len, TPMS_PCR_SELECTION *pcrSel);
int pcr_parse_arg(char *arg, UINT32 *pcrId, BYTE *forwardHash);

typedef struct pcr_struct {
	UINT32 pcr;
	BYTE forwardHash[32];
} pcr_struct;

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


#endif /* SRC_PCR_H_ */
