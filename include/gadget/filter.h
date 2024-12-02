/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef FILTER_H
#define FILTER_H

#include <bpf/bpf_helpers.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/mntns_filter.h>

#define GADGET_INVALID_ID ((uid_t)-1)

// user space terminology
const volatile gadget_pid targ_pid = 0;
GADGET_PARAM(targ_pid);

const volatile gadget_tid targ_tid = 0;
GADGET_PARAM(targ_tid);

const volatile gadget_uid targ_uid = GADGET_INVALID_ID;
GADGET_PARAM(targ_uid);

const volatile gadget_gid targ_gid = GADGET_INVALID_ID;
GADGET_PARAM(targ_gid);

const volatile gadget_comm targ_comm[TASK_COMM_LEN] = {};
GADGET_PARAM(targ_comm);

// gadget_should_discard_event returns true if the gadget should drop this
// event. This function uses the current mount namespace, pid, tid, uid, and gid
// to determine if the event should be dropped.
static __always_inline bool gadget_should_discard_event()
{
	if (gadget_should_discard_mntns_id(gadget_get_mntns_id()))
		return true;

	if (targ_pid != 0 || targ_tid != 0) {
		// user space terminology used here
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		__u32 pid = pid_tgid >> 32;
		__u32 tid = pid_tgid;

		if (targ_pid && targ_pid != pid)
			return true;

		if (targ_tid && targ_tid != tid)
			return true;
	}

	if (targ_uid != GADGET_INVALID_ID || targ_gid != GADGET_INVALID_ID) {
		__u64 uid_gid = bpf_get_current_uid_gid();
		__u32 uid = uid_gid;
		__u32 gid = uid_gid >> 32;

		if (targ_uid != GADGET_INVALID_ID && targ_uid != uid)
			return true;

		if (targ_gid != GADGET_INVALID_ID && targ_gid != gid)
			return true;
	}

	if (targ_comm[0] != '\0') {
		char comm[TASK_COMM_LEN];
		bpf_get_current_comm(&comm, sizeof(comm));
		for (int i = 0; i < sizeof(comm); i++) {
			if (comm[i] == '\0' || targ_comm[i] == '\0') {
				break;
			}

			if (comm[i] != targ_comm[i]) {
				return true;

			}
		}
	}

	return false;
}

#endif
