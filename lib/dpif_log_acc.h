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
#ifndef DPIF_LOG_ACC_H
#define DPIF_LOG_ACC_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "netdev.h"
#include "dp-packet.h"
#include "openflow/openflow.h"
#include "ovs-numa.h"
#include "packets.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

#if 0
void log_operation_acc(const struct dpif *, const char *operation,
                   int error);
#endif

void log_flow_put_message_acc(struct dpif *, const struct dpif_flow_put *,
                          int error, struct dp_packet *packet);
void log_flow_del_message_acc(struct dpif *, const struct dpif_flow_del *,
                          int error);
#if 0
void log_flow_get_message_acc(const struct dpif *,
                          const struct dpif_flow_get *, int error);
void log_execute_message_acc(struct dpif *, const struct dpif_execute *,
                         bool subexecute, int error);
#endif

#endif /* dpif_log_acc.h */

