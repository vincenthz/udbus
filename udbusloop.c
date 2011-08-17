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

#include <string.h>
#include "udbusloop.h"

int dbus_dispatch_new(dbus_dispatch_ctx *ctx, dbus_io *dio)
{
	memset(ctx, '\0', sizeof(dbus_dispatch_ctx));
	ctx->dio = dio;
	dbus_event_init(&ctx->part);
	return 0;
}

int dbus_dispatch_get_fd(dbus_dispatch_ctx *ctx)
{
	return dbus_event_get_fd(ctx->dio);
}

/* expected  == null = 1 */
/* got       == null = 0 */
/* otherwise         = expected == got */
static int string_matching(char *expected, char *got)
{
	if (!expected) return 1;
	if (!got) return 0;
	return strcmp(expected, got) == 0;
}

static int match_rule(dbus_dispatch_rule *rule, dbus_msg *msg)
{
	int matched = 1;
	matched = string_matching(rule->m_destination, msg->destination);
	if (matched) matched = string_matching(rule->m_path, msg->path);
	if (matched) matched = string_matching(rule->m_interface, msg->interface);
	if (matched) matched = string_matching(rule->m_method, msg->method);
	if (matched) matched = string_matching(rule->m_error_name, msg->error_name);
	if (matched) matched = string_matching(rule->m_sender, msg->sender);
	return matched;
}

static void dbus_dispatch_throwaway(dbus_dispatch_ctx *ctx, dbus_msg *msg)
{
	/* TODO callback in dispatch to log */
	dbus_msg_free(msg);
}

static int dbus_dispatch_with_rule(dbus_dispatch_ctx *ctx, dbus_dispatch_rule *rule, dbus_msg *msg)
{
	while (rule != NULL) {
		if (match_rule(rule, msg)) {
			return rule->f(rule->priv, msg);
		}
		rule = rule->next;
	}
	dbus_dispatch_throwaway(ctx, msg);
	return 1;
}

static int dbus_dispatch_method(dbus_dispatch_ctx *ctx, dbus_msg *msg)
{
	return dbus_dispatch_with_rule(ctx, ctx->method_table, msg);
}

static int dbus_dispatch_signal(dbus_dispatch_ctx *ctx, dbus_msg *msg)
{
	return dbus_dispatch_with_rule(ctx, ctx->signal_table, msg);
}

static int dbus_dispatch_reply(dbus_dispatch_ctx *ctx, dbus_msg *msg)
{
	dbus_dispatch_reply_rule *prev = NULL;
	dbus_dispatch_reply_rule *rule = ctx->return_table;
	if (!rule) {
		dbus_dispatch_throwaway(ctx, msg);
		return 1;
	}

	while (rule != NULL) {
		if (rule->m_reply_serial == msg->reply_serial) {
			/* unregister matching rule */
			if (!prev) {
				ctx->return_table = ctx->return_table->next;
			} else {
				prev->next = rule->next;
			}
			return rule->f(rule->priv, msg);
		}
		prev = rule;
		rule = rule->next;
	}

	/* no matching :/ */
	dbus_dispatch_throwaway(ctx, msg);
	return 1;
}

int dbus_dispatch_process_read(dbus_dispatch_ctx *ctx)
{
	dbus_msg *msg;

	dbus_event_recv(ctx->dio, &ctx->part, &msg);
	if (dbus_event_has_message(&ctx->part)) {
		switch (msg->type) {
		case DBUS_TYPE_ERROR: /* fallthrough method return */
		case DBUS_TYPE_METHOD_RETURN: dbus_dispatch_reply(ctx, msg); break;
		case DBUS_TYPE_METHOD_CALL: dbus_dispatch_method(ctx, msg); break;
		case DBUS_TYPE_SIGNAL: dbus_dispatch_signal(ctx, msg); break;
		}
		dbus_event_init(&ctx->part);
	}
	return 0;
}

int dbus_register_signal(dbus_dispatch_ctx *ctx, dbus_dispatch_rule *rule)
{
	rule->next = ctx->signal_table;
	ctx->signal_table = rule;
	return 0;
}

int dbus_register_method(dbus_dispatch_ctx *ctx, dbus_dispatch_rule *rule)
{
	rule->next = ctx->method_table;
	ctx->method_table = rule;
	return 0;
}

int dbus_register_reply(dbus_dispatch_ctx *ctx, dbus_dispatch_reply_rule *rule)
{
	rule->next = ctx->return_table;
	ctx->return_table = rule;
	return 0;
}

int dbus_dispatch_send_async(dbus_dispatch_ctx *ctx, dbus_msg *msg, dbus_msg *ret)
{
	dbus_register_reply(ctx, msg->serial);
	return 0;
}
