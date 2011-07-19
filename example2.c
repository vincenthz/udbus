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

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>

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
	int r = read(fd, buf, count);
	return r;
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

int io_get_fd(void *priv)
{
	int fd = *((int *) priv);
	return fd;
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

void add_match(dbus_io *dio, char *s)
{
	dbus_msg *msg, *recv;
	dbus_sig signature;

	msg = dbus_msg_new_method_call(dio->next_serial++,
	                               "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                               "org.freedesktop.DBus", "AddMatch");
        if (!msg) {
		exit(1);
	}
	signature.a[0] = DBUS_STRING;
	signature.a[1] = DBUS_INVALID;
	dbus_msg_set_signature(msg, &signature);
	dbus_msg_body_add(msg, 4096);
	dbus_msg_body_add_string(msg, s);

	printf("=> adding match for \"%s\"\n", s);
        dbus_msg_send(dio, msg);
	dbus_msg_recv(dio, &recv);
	print_message(recv, 1);
}

int main(int argc, char **argv)
{
	int fd;
	int uid;
	char hexencoded_uid[32];
	char authline[256];
	dbus_msg *msg, *recv;
	dbus_io dio;

	fd = dbus_connect_session();
	if (fd == -1) {
		printf("failed connection to session bus\n");
		exit(1);
	}

	dio.io_read = io_read;
	dio.io_write = io_write;
	dio.priv = (void *) &fd;
	dio.io_get_fd = io_get_fd;
	dio.io_debug = io_debug;
	dio.logpriv = NULL;
	dio.next_serial = 1;

	uid = getuid();
	
	hexencode(hexencoded_uid, uid);
	sprintf(authline, "EXTERNAL %s", hexencoded_uid);

	dbus_auth(&dio, authline);

	msg = dbus_msg_new_method_call(dio.next_serial++,
	                               "org.freedesktop.DBus", "/org/freedesktop/DBus",
	                               "org.freedesktop.DBus", "Hello");
	if (!msg) {
		exit(1);
	}
	dbus_msg_send(&dio, msg);
	dbus_msg_recv(&dio, &recv);

	/* received a name acquired signal */
	dbus_msg_recv(&dio, &recv);

	add_match(&dio, "type='signal'");
	add_match(&dio, "type='method_call'");
	add_match(&dio, "type='method_return'");
	add_match(&dio, "type='error'");

	{
		fd_set set;
		dbus_eventpart ev;
		dbus_msg *msg;
		int sfd = dbus_event_get_fd(&dio);

		dbus_event_init(&ev);
		FD_ZERO(&set);
		while (1) {
			FD_SET(sfd, &set);
			int r = select(sfd+1, &set, NULL, NULL, NULL);
			if (FD_ISSET(sfd, &set)) {
				dbus_event_recv(&dio, &ev, &msg);
				if (dbus_event_has_message(&ev)) {
					print_message(msg, 1);
					dbus_event_init(&ev);
					dbus_msg_free(msg);
				}
			}
		}
	}

	return 0;
}
