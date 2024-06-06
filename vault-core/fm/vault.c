#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <cryptoki.h>
#include <privilege.h>

#include "fm/hsm/fmsw.h"
#include "fm/hsm/fm.h"
#include "fm/common/fm_byteorder.h"
#include "fm/hsm/fm_io_service.h"

#include "vault.h"

static int fmHandler(FmMsgHandle token)
{
    int rv = CKR_OK;

    unsigned char in_buf[FM_MAX_BUFFER_SIZE];
    uint32_t in_len = 0;
    unsigned char out_buf[FM_MAX_BUFFER_SIZE];
    uint32_t out_len = 0;

    in_len = SVC_IO_Read(token, &in_buf, sizeof(in_buf));

    CT_SetPrivilegeLevel(PRIVILEGE_OVERRIDE);

    handler_c(in_buf, in_len, out_buf, &out_len);

    CT_SetPrivilegeLevel(PRIVILEGE_NORMAL);

    SVC_IO_Write(token, out_buf, out_len);

    return rv;
}

FM_RV Startup(void)
{
    FM_RV rv = FMSW_RegisterStreamDispatch(GetFMID(), fmHandler);
    return rv;
}