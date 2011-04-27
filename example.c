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

#include "udbus.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

void hexencode(char *d, int v)
{
	char buf[32];
	int i;

	sprintf(buf, "%d", v);
	for (i = 0; buf[i]; i++) {
		sprintf(d, "%.2x", buf[i]);
		d += 2;
	}
}

int io_read(void *priv, void *buf, uint32_t count)
{
	int fd = *((int *) priv);
	uint32_t offset = 0;
	while (offset < count) {
		int r = read(fd, buf + offset, count - offset);
		if (r <= 0) {
			fprintf(stderr, "fail reading: %d\n", r);
			return -1;
		}
		offset += r;
	}
	return 0;
}

int io_write(void *priv, const void *buf, uint32_t count)
{
	int fd = *((int *) priv);
	uint32_t offset = 0;
	while (offset < count) {
		int r = write(fd, buf + offset, count - offset);
		if (r <= 0) {
			fprintf(stderr, "fail reading: %d\n", errno);
			return -1;
		}
		offset += r;
	}
	return 0;
}

void io_debug(void *priv, const char *s)
{
	fprintf(stderr, "debug: %s\n", s);
}

void print_message(dbus_msg *msg, int with_header)
{
	dbus_type *ptr = msg->signature.a;
	if (with_header) {
		char *ty;
		switch (msg->type) {
		case DBUS_TYPE_INVALID      : ty = "invalid"; break;
		case DBUS_TYPE_METHOD_CALL  : ty = "method-call"; break;
		case DBUS_TYPE_METHOD_RETURN: ty = "method-return"; break;
		case DBUS_TYPE_ERROR        : ty = "error"; break;
		case DBUS_TYPE_SIGNAL       : ty = "signal"; break;
		default                     : ty = "unknown"; break;
		}
		printf("type: %s\n", ty);
		printf("serial: %u\n", msg->serial);
		if (msg->destination) printf("destination: %s\n", msg->destination);
		if (msg->path) printf("path: %s\n", msg->path);
		if (msg->interface) printf("interface: %s\n", msg->interface);
		if (msg->method) printf("method: %s\n", msg->method);
		if (msg->error_name) printf("error_name: %s\n", msg->error_name);
		if (msg->sender) printf("sender: %s\n", msg->sender);
	}
}

int main(int argc, char **argv)
{
	int fd;
	int uid;
	char hexencoded_uid[32];
	char authline[256];
	dbus_array_reader aread;
	dbus_array_writer awriter;
	dbus_sig signature;
	dbus_msg *msg, *recv;
	dbus_io dio;
	int serial = 1;
	int err;

	fd = dbus_connect_session();
	if (fd == -1) {
		printf("failed connection to session bus\n");
		exit(1);
	}

	dio.io_read = io_read;
	dio.io_write = io_write;
	dio.priv = (void *) &fd;
	dio.io_debug = io_debug;
	dio.logpriv = NULL;

	uid = getuid();
	
	hexencode(hexencoded_uid, uid);
	sprintf(authline, "EXTERNAL %s", hexencoded_uid);

	dbus_auth(&dio, authline);

	msg = dbus_msg_new_method_call(serial++,
	                               "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                               "org.freedesktop.DBus", "Hello");
	if (!msg) {
		exit(1);
	}
	dbus_msg_send(&dio, msg);
	dbus_msg_recv(&dio, &recv);

	/* received a name acquired signal */
	dbus_msg_recv(&dio, &recv);

	msg = dbus_msg_new_method_call(serial++,
	                               "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                               "org.freedesktop.DBus", "ListNames");
	if (!msg) {
		exit(1);
	}
	dbus_msg_send(&dio, msg);
	dbus_msg_recv(&dio, &recv);

	dbus_msg_body_get_array(recv, &aread);
	while (dbus_msg_body_get_array_left(recv, &aread) > 0) {
		char *val;
		dbus_msg_body_get_string(recv, &val);
		printf("s: %s\n", val);
	}

	msg = dbus_msg_new_method_call(serial++,
	                               "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                               "org.freedesktop.DBus", "AddMatch");
        if (!msg) {
		exit(1);
	}
	signature.a[0] = DBUS_STRING;
	signature.a[1] = DBUS_INVALID;
	dbus_msg_set_signature(msg, &signature);
	dbus_msg_body_add(msg, 4096);
	dbus_msg_body_add_string(msg, "type='method_call'");
        dbus_msg_send(&dio, msg);

	dbus_msg_recv(&dio, &recv);

	msg = dbus_msg_new_method_call(serial++,
	                               "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
	                               "org.freedesktop.Notifications", "Notify");
	signature.a[0] = DBUS_STRING;
	signature.a[1] = DBUS_UINT32;
	signature.a[2] = DBUS_STRING;
	signature.a[3] = DBUS_STRING;
	signature.a[4] = DBUS_STRING;
	signature.a[5] = DBUS_ARRAY;
	signature.a[6] = DBUS_STRING;
	signature.a[7] = DBUS_ARRAY;
	signature.a[8] = DBUS_DICT_BEGIN;
	signature.a[9] = DBUS_STRING;
	signature.a[10] = DBUS_VARIANT;
	signature.a[11] = DBUS_DICT_END;
	signature.a[12] = DBUS_INT32;
	signature.a[13] = DBUS_INVALID;
	dbus_msg_set_signature(msg, &signature);
	dbus_msg_body_add(msg, 4096);
	dbus_msg_body_add_string(msg, "y");
	dbus_msg_body_add_uint32(msg, 1);
	dbus_msg_body_add_string(msg, "x");
	dbus_msg_body_add_string(msg, "this is a string");
	dbus_msg_body_add_string(msg, "this is a o----");
	dbus_msg_body_add_array_begin(msg, signature.a[6], &awriter);
	dbus_msg_body_add_array_end(msg, &awriter);
	dbus_msg_body_add_array_begin(msg, signature.a[8], &awriter);
	dbus_msg_body_add_array_end(msg, &awriter);
	dbus_msg_body_add_int32(msg, 4000);
	dbus_msg_send(&dio, msg);

	err = dbus_msg_recv(&dio, &recv);
	if (err) {
		printf("error receiving message %d\n", err);
		exit(2);
	}
	print_message(recv, 1);

	return 0;
}
