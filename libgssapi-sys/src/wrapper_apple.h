#include <GSS/GSS.h>
#include "consts.h"

typedef struct gss_cred_id_t_desc_struct gss_cred_id_struct;
typedef struct gss_name_t_desc_struct gss_name_struct;

OM_uint32 KRB5_CALLCONV ___ApplePrivate_gss_wrap_iov
(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    gss_iov_buffer_desc *,    /* iov */
    int);		/* iov_count */

OM_uint32 KRB5_CALLCONV ___ApplePrivate_gss_unwrap_iov
(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int *,		/* conf_state */
    gss_qop_t *,	/* qop_state */
    gss_iov_buffer_desc *,    /* iov */
    int);		/* iov_count */

OM_uint32 KRB5_CALLCONV ___ApplePrivate_gss_wrap_iov_length
(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    gss_iov_buffer_desc *, /* iov */
    int);		/* iov_count */

