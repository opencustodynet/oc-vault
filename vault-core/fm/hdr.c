#include <mkfmhdr.h>

#include "fm/hsm/fm.h"

#define VAULT_FM_ID FMID_ALLOCATE_NORM
#define VAULT_FM_PRODUCT_ID "opencustody_fm"
#define VAULT_FM_MANUFACTURER_ID "opencustody"

DEFINE_FM_HEADER(VAULT_FM_ID,
                 FM_MAKE_VERSION(1, 01),
                 0,
                 VAULT_FM_MANUFACTURER_ID,
                 VAULT_FM_PRODUCT_ID);
