/*
 * Copyright (c) 2017 Accton, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "dpif-provider.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "coverage.h"
#include "dpctl.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "flow.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "route-table.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "util.h"
#include "uuid.h"
#include "valgrind.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/vlog.h"
#include "dpif_log_acc.h"

#define ACC_PERMIT_STR  "result:permit"
#define ACC_DROP_STR    "result:drop"

VLOG_DEFINE_THIS_MODULE(dpif_sess);

enum log_flow_message_type {
    LF_MSG_PUT,
    LF_MSG_DEL,
    LF_MSG_GET
};

/* Rate limit for individual messages. */
static struct vlog_rate_limit dpmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Not really much point in logging many dpif errors. */
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static void log_flow_message_acc(const struct dpif *dpif, int error,
                             const char *operation,
                             const struct nlattr *key, size_t key_len,
                             const struct nlattr *mask, size_t mask_len,
                             const ovs_u128 *ufid,
                             const struct dpif_flow_stats *stats,
                             const struct nlattr *actions, size_t actions_len,
                             enum log_flow_message_type lf_type);

static bool should_log_flow_message_acc(int error);

#if 0
static bool dpif_execute_needs_help_acc(const struct dpif_execute *execute);

#endif

#if 0
void
log_operation_acc(const struct dpif *dpif, const char *operation, int error)
{
    if (!error) {
        VLOG_DBG_RL(&dpmsg_rl, "%s: %s success", dpif_name(dpif), operation);
    } else if (ofperr_is_valid(error)) {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, ofperr_get_name(error));
    } else {
        VLOG_WARN_RL(&error_rl, "%s: %s failed (%s)",
                     dpif_name(dpif), operation, ovs_strerror(error));
    }
}
#endif

void
log_flow_put_message_acc(struct dpif *dpif, const struct dpif_flow_put *put,
                     int error, struct dp_packet *packet)
{
    if (should_log_flow_message_acc(error) && !(put->flags & DPIF_FP_PROBE)) {
        struct ds s;

        ds_init(&s);
        ds_put_cstr(&s, "put");
        if (put->flags & DPIF_FP_CREATE) {
            ds_put_cstr(&s, "[create]");
        }
        if (put->flags & DPIF_FP_MODIFY) {
            ds_put_cstr(&s, "[modify]");
        }
        if (put->flags & DPIF_FP_ZERO_STATS) {
            ds_put_cstr(&s, "[zero]");
        }
        log_flow_message_acc(dpif, error, ds_cstr(&s),
                         put->key, put->key_len, put->mask, put->mask_len,
                         put->ufid, put->stats, put->actions,
                         put->actions_len,
                         LF_MSG_PUT);
        ds_destroy(&s);
    }
}

void
log_flow_del_message_acc(struct dpif *dpif, const struct dpif_flow_del *del,
                     int error)
{
    if (should_log_flow_message_acc(error)) {
        log_flow_message_acc(dpif, error, "flow_del", del->key, del->key_len,
                         NULL, 0, del->ufid, !error ? del->stats : NULL,
                         NULL, 0, LF_MSG_DEL);
    }
}

#if 0
void
log_flow_get_message_acc(const struct dpif *dpif, const struct dpif_flow_get *get,
                     int error)
{
    if (should_log_flow_message_acc(error)) {
        log_flow_message_acc(dpif, error, "flow_get",
                         get->key, get->key_len,
                         get->flow->mask, get->flow->mask_len,
                         get->ufid, &get->flow->stats,
                         get->flow->actions, get->flow->actions_len, LF_MSG_GET);
    }
}

/* Logs that 'execute' was executed on 'dpif' and completed with errno 'error'
 * (0 for success).  'subexecute' should be true if the execution is a result
 * of breaking down a larger execution that needed help, false otherwise.
 *
 *
 * XXX In theory, the log message could be deceptive because this function is
 * called after the dpif_provider's '->execute' function, which is allowed to
 * modify execute->packet and execute->md.  In practice, though:
 *
 *     - dpif-netlink doesn't modify execute->packet or execute->md.
 *
 *     - dpif-netdev does modify them but it is less likely to have problems
 *       because it is built into ovs-vswitchd and cannot have version skew,
 *       etc.
 *
 * It would still be better to avoid the potential problem.  I don't know of a
 * good way to do that, though, that isn't expensive. */
void
log_execute_message_acc(struct dpif *dpif, const struct dpif_execute *execute,
                    bool subexecute, int error)
{
    if (!(error ? VLOG_DROP_WARN(&error_rl) : VLOG_DROP_DBG(&dpmsg_rl))
        && !execute->probe) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet;

        packet = ofp_packet_to_string(dp_packet_data(execute->packet),
                                      dp_packet_size(execute->packet));
        ds_put_format(&ds, "%s: %sexecute ",
                      dpif_name(dpif),
                      (subexecute ? "sub-"
                       : dpif_execute_needs_help_acc(execute) ? "super-"
                       : ""));
        format_odp_actions(&ds, execute->actions, execute->actions_len);
        if (error) {
            ds_put_format(&ds, " failed (%s)", ovs_strerror(error));
        }
        ds_put_format(&ds, " on packet %s", packet);
        ds_put_format(&ds, " mtu %d", execute->mtu);
        vlog(&this_module, error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
        free(packet);
    }
}

#endif

static enum vlog_level
flow_message_log_level_acc(int error)
{
    /* If flows arrive in a batch, userspace may push down multiple
     * unique flow definitions that overlap when wildcards are applied.
     * Kernels that support flow wildcarding will reject these flows as
     * duplicates (EEXIST), so lower the log level to debug for these
     * types of messages. */
    return (error && error != EEXIST) ? VLL_WARN : VLL_DBG;
}

static bool
should_log_flow_message_acc(int error)
{
    return !vlog_should_drop(&this_module, flow_message_log_level_acc(error),
                             error ? &error_rl : &dpmsg_rl);
}

static bool has_output_action_acc(const struct nlattr *actions, size_t actions_len)
{
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
        enum ovs_action_attr type = nl_attr_type(a);
        if (type == OVS_ACTION_ATTR_OUTPUT)
            return true;
    }

    return false;
}

static void
log_flow_message_acc(const struct dpif *dpif, int error, const char *operation,
                 const struct nlattr *key, size_t key_len,
                 const struct nlattr *mask, size_t mask_len,
                 const ovs_u128 *ufid, const struct dpif_flow_stats *stats,
                 const struct nlattr *actions, size_t actions_len,
                 enum log_flow_message_type lf_type)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format(&ds, "%s: ", dpif_name(dpif));
    if (error) {
        ds_put_cstr(&ds, "failed to ");
    }
    ds_put_format(&ds, "%s ", operation);
    if (error) {
        ds_put_format(&ds, "(%s) ", ovs_strerror(error));
    }
    if (ufid) {
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " ");
    }
    odp_flow_format(key, key_len, mask, mask_len, NULL, &ds, true);
    if (stats) {
        ds_put_cstr(&ds, ", ");
        dpif_flow_stats_format(stats, &ds);
    }
    if (actions || actions_len) {
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);

        if (has_output_action_acc(actions, actions_len))
        {
            ds_put_cstr(&ds, ", " ACC_PERMIT_STR);
        }
    } else {
        if (lf_type == LF_MSG_PUT) {
            ds_put_cstr(&ds, ", " ACC_DROP_STR);
        }
    }
    vlog(&this_module, flow_message_log_level_acc(error), "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

#if 0
/* Returns true if the datapath needs help executing 'execute'. */
static bool
dpif_execute_needs_help_acc(const struct dpif_execute *execute)
{
    return execute->needs_help || nl_attr_oversized(execute->actions_len);
}
#endif

