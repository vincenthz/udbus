/*
 * Copyright (c) 2010-2011 Vincent Hanquez <vincent@snarc.org>
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef UDBUS_LOOP_H
#define UDBUS_LOOP_H

#include "udbus.h"

typedef struct dbus_dispatch_reply_rule {
	int m_reply_serial;
	void *priv;
	int (*f)(void *priv, dbus_msg *msg);
	struct dbus_dispatch_reply_rule *next;
} dbus_dispatch_reply_rule;

typedef struct dbus_dispatch_rule {
	char *m_destination;
	char *m_path;
	char *m_interface;
	char *m_method;
	char *m_error_name;
	char *m_sender;
	void *priv;
	int (*f)(void *priv, dbus_msg *msg);
	struct dbus_dispatch_rule *next;
} dbus_dispatch_rule;

typedef struct {
	dbus_io *dio;
	dbus_eventpart part;
	dbus_dispatch_rule *signal_table; /* signal_call */
	dbus_dispatch_rule *method_table; /* method_call */
	dbus_dispatch_reply_rule *return_table; /* error + method_return */
} dbus_dispatch_ctx;

/* create a new dispatcher context */
int dbus_dispatch_new(dbus_dispatch_ctx *ctx, dbus_io *dio);

/* use to register file descriptor to a polling loop */
int dbus_dispatch_get_fd(dbus_dispatch_ctx *ctx);

/* make the dispatcher read once from io, and if having a complete message,
 * will wakeup with right callback */
int dbus_dispatch_process_read(dbus_dispatch_ctx *ctx);

#endif
