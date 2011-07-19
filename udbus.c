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
#include <string.h>
#include <stdio.h>

#define HAVE_UNIX_SOCKET 1

struct header {
	uint8_t endianness; /* 0 = little endian, 1 = big endian */
	uint8_t messagetype;
	uint8_t flags;
	uint8_t ver;
	uint32_t bodylen;
	uint32_t serial;
	uint32_t fieldslen;
};

static void reader_initialize(struct dbus_reader *reader, int align_offset, int length)
{
	reader->align_offset = align_offset;
	reader->length = length;
	reader->offset = 0;
}

static int read_line(dbus_io *dio, char *buf, int len)
{
	int offset = 0, found = 0, r = 0;
	memset(buf, '\0', len);
	do {
		if (offset == len)
			return -9;
		r = dio->io_read(dio->priv, buf + offset, 1);
		if (r)
			return r;
		if (buf[offset] == '\n')
			found = 1;
		offset++;
	} while (!found);
	return (found) ? 0 : -10;
}

#ifdef DEBUG
static void hexdump(const uint8_t *s, int len)
{
	int i;
	for (i = 0; i < 16; i++)
		printf("%.2x ", s[i]);
	printf("\n");
}

static void print_header(struct header *header)
{
	printf("header: %d\n", header->messagetype);
	printf("header: %d\n", header->flags);
	printf("header: %d\n", header->ver);
	printf("header: %d\n", header->bodylen);
	printf("header: %d\n", header->serial);
	printf("header: %d\n", header->fieldslen);
}

static void print_msg(dbus_msg *msg)
{
	printf("msg ty         : %d\n", msg->type);
	printf("msg dest       : %s\n", msg->destination);
	printf("msg path       : %s\n", msg->path);
	printf("msg interface  : %s\n", msg->interface);
	printf("msg method     : %s\n", msg->method);
	printf("msg error_name : %s\n", msg->error_name);
	printf("msg sender     : %s\n", msg->sender);
	printf("msg sig        : %s\n", msg->signature);
	printf("msg reply seria: %d\n", msg->reply_serial);
}
#endif

static void dio_debug(dbus_io *dio, char *s)
{
	if (dio->io_debug)
		dio->io_debug(dio->logpriv, s);
}

/****************************************************************************/
/* low level */

static uint32_t swap32(uint32_t a) { return (a << 24) | ((a & 0xff00) << 8) | ((a >> 8) & 0xff00) | (a >> 24); }

uint32_t ALIGN_VALUE(uint32_t x, uint32_t n) { return ((x-1+n) & (~(n-1))); }

#define check_read(i) if (reader->offset + i > reader->length) { printf("%s: checkread failure offset=%d n=%d len=%d\n", __FUNCTION__, reader->offset, i, reader->length); return (-1);}
#define check_write(i) if (writer->offset + i > writer->length) return (-1)

static int align_read(struct dbus_reader *reader, int alignment)
{
	int ax = reader->align_offset + reader->offset;
	int toalign = alignment - (ax % alignment);

	if (toalign < alignment) {
		check_read(toalign);
		reader->offset += toalign;
	}
	return 0;
}

static int align_write(struct dbus_writer *writer, int alignment)
{
	int ax = writer->offset;
	int toalign = alignment - (ax % alignment);

	if (toalign < alignment) {
		int i;
		check_write(toalign);

		for (i = 0; i < toalign; i++)
			writer->buffer[writer->offset++] = '\0';
	}
	return 0;
}

static int get_w8(struct dbus_reader *reader, uint8_t *r)
{
	check_read(1);
	if (r) *r = reader->data[reader->offset++];
	return 0;
}

static int get_w16(struct dbus_reader *reader, uint16_t *r)
{
	uint16_t v;
	align_read(reader, 2);
	check_read(2);
	if (reader->endianness) {
		v = reader->data[reader->offset++] << 8;
		v |= reader->data[reader->offset++];
	} else {
		v = reader->data[reader->offset++];
		v |= reader->data[reader->offset++] << 8;
	}
	if (r) *r = v;
	return 0;
}

static int get_w32(struct dbus_reader *reader, uint32_t *r)
{
	uint32_t v;
	align_read(reader, 4);
	check_read(4);

	v  = reader->data[reader->offset++];
	v |= reader->data[reader->offset++] << 8;
	v |= reader->data[reader->offset++] << 16;
	v |= reader->data[reader->offset++] << 24;
	if (reader->endianness)
		v = swap32(v);
	if (r) *r = v;
	return 0;
}

static int get_w64(struct dbus_reader *reader, uint64_t *r)
{
	uint32_t v1,v2;

	align_read(reader, 8);
	check_read(8);
	get_w32(reader, &v1);
	get_w32(reader, &v2);
	*r = (reader->endianness)
		? (((uint64_t) v1) << 32) | ((uint64_t) v2)
		: (((uint64_t) v2) << 32) | ((uint64_t) v1);
	return 0;
}

static int get_string(struct dbus_reader *reader, char **s)
{
	int r = 0, i;
	uint32_t len;
	uint8_t nullbyte;
	char *ret;

	r |= get_w32(reader, &len);
	if (r)
		return r;

	ret = calloc(len+1, sizeof(char));
	if (!ret)
		return -1;

	for (i = 0; i < len; i++) {
		r |= get_w8(reader, (uint8_t *) ret + i);
		if (r) break;
	}
	r |= get_w8(reader, &nullbyte);
	if (r || nullbyte != '\0') {
		*s = NULL;
		free(ret);
		return (r) ? r : -2;
	}
	*s = ret;
	return r;
}

static int put_w8(struct dbus_writer *writer, uint8_t v)
{
	check_write(1);
	writer->buffer[writer->offset++] = v;
	return 0;
}

static int put_w16(struct dbus_writer *writer, uint16_t v)
{
	align_write(writer, 2);
	check_write(2);
	if (writer->endianness) {
		writer->buffer[writer->offset++] = (v >> 8) & 0xff;
		writer->buffer[writer->offset++] = (v) & 0xff;
	} else {
		writer->buffer[writer->offset++] = (v) & 0xff;
		writer->buffer[writer->offset++] = (v >> 8) & 0xff;
	}
	return 0;
}

static int put_w32(struct dbus_writer *writer, uint32_t v)
{
	align_write(writer, 4);
	check_write(4);
	if (writer->endianness) {
		writer->buffer[writer->offset++] = (v >> 24) & 0xff;
		writer->buffer[writer->offset++] = (v >> 16) & 0xff;
		writer->buffer[writer->offset++] = (v >> 8) & 0xff;
		writer->buffer[writer->offset++] = (v) & 0xff;
	} else {
		writer->buffer[writer->offset++] = (v) & 0xff;
		writer->buffer[writer->offset++] = (v >> 8) & 0xff;
		writer->buffer[writer->offset++] = (v >> 16) & 0xff;
		writer->buffer[writer->offset++] = (v >> 24) & 0xff;
	}
	return 0;
}

static int put_var_w32(struct dbus_writer *writer, uint32_t **ptr)
{
	align_write(writer, 4);
	check_write(4);
	*ptr = (uint32_t *) (writer->buffer + writer->offset);
	writer->offset += 4;
	return 0;
}

static int put_w64(struct dbus_writer *writer, uint64_t v)
{
	align_write(writer, 8);
	check_write(8);
	if (writer->endianness) {
		writer->buffer[writer->offset++] = (v >> 56) & 0xff;
		writer->buffer[writer->offset++] = (v >> 48) & 0xff;
		writer->buffer[writer->offset++] = (v >> 40) & 0xff;
		writer->buffer[writer->offset++] = (v >> 32) & 0xff;
		writer->buffer[writer->offset++] = (v >> 24) & 0xff;
		writer->buffer[writer->offset++] = (v >> 16) & 0xff;
		writer->buffer[writer->offset++] = (v >> 8) & 0xff;
		writer->buffer[writer->offset++] = (v) & 0xff;
	} else {
		writer->buffer[writer->offset++] = (v) & 0xff;
		writer->buffer[writer->offset++] = (v >> 8) & 0xff;
		writer->buffer[writer->offset++] = (v >> 16) & 0xff;
		writer->buffer[writer->offset++] = (v >> 24) & 0xff;
		writer->buffer[writer->offset++] = (v >> 32) & 0xff;
		writer->buffer[writer->offset++] = (v >> 40) & 0xff;
		writer->buffer[writer->offset++] = (v >> 48) & 0xff;
		writer->buffer[writer->offset++] = (v >> 56) & 0xff;
	}
	return 0;
}

static int put_string(struct dbus_writer *writer, const char *s, uint32_t len)
{
	int r = 0, i;

	r |= put_w32(writer, len);
	for (i = 0; i < len; i++)
		r |= put_w8(writer, s[i]);
	r |= put_w8(writer, '\0');
	return r;
}

static int alignment_of_type(dbus_type type)
{
	switch (type) {
	case DBUS_SIGNATURE: return 1;
	case DBUS_OBJECTPATH: return 4;
	case DBUS_BOOLEAN: return 4;
	case DBUS_BYTE: return 1;
	case DBUS_STRING: return 4;
	case DBUS_INT16: return 2;
	case DBUS_UINT16: return 2;
	case DBUS_INT32: return 4;
	case DBUS_UINT32: return 4;
	case DBUS_INT64: return 8;
	case DBUS_UINT64: return 8;
	case DBUS_DOUBLE: return 8;
	case DBUS_ARRAY: return 4;
	case DBUS_VARIANT: return 1;
	case DBUS_STRUCT_BEGIN: return 8;
	case DBUS_STRUCT_END: return 0;
	case DBUS_DICT_BEGIN: return 8;
	case DBUS_DICT_END: return 0;
	default: return -1;
	}
}

static int sig_elem_of_char(char c, dbus_type *sig)
{
	switch (c) {
	case 'g': *sig = DBUS_SIGNATURE; return 0;
	case 'o': *sig = DBUS_OBJECTPATH; return 0;
	case 'b': *sig = DBUS_BOOLEAN; return 0;
	case 'y': *sig = DBUS_BYTE; return 0;
	case 's': *sig = DBUS_STRING; return 0;
	case 'n': *sig = DBUS_INT16; return 0;
	case 'q': *sig = DBUS_UINT16; return 0;
	case 'i': *sig = DBUS_INT32; return 0;
	case 'u': *sig = DBUS_UINT32; return 0;
	case 'x': *sig = DBUS_INT64; return 0;
	case 't': *sig = DBUS_UINT64; return 0;
	case 'd': *sig = DBUS_DOUBLE; return 0;
	case 'a': *sig = DBUS_ARRAY; return 0;
	case 'v': *sig = DBUS_VARIANT; return 0;
	case '(': *sig = DBUS_STRUCT_BEGIN; return 0;
	case ')': *sig = DBUS_STRUCT_END; return 0;
	case '{': *sig = DBUS_DICT_BEGIN; return 0;
	case '}': *sig = DBUS_DICT_END; return 0;
	default: return -1;
	}
}

static int char_of_sig_elem(dbus_type sig, char *c)
{
	switch (sig) {
	case DBUS_SIGNATURE: *c = 'g'; return 0;
	case DBUS_OBJECTPATH: *c = 'o'; return 0;
	case DBUS_BOOLEAN: *c = 'b'; return 0;
	case DBUS_BYTE: *c = 'y'; return 0;
	case DBUS_STRING: *c = 's'; return 0;
	case DBUS_INT16: *c = 'n'; return 0;
	case DBUS_UINT16: *c = 'q'; return 0;
	case DBUS_INT32: *c = 'i'; return 0;
	case DBUS_UINT32: *c = 'u'; return 0;
	case DBUS_INT64: *c = 'x'; return 0;
	case DBUS_UINT64: *c = 't'; return 0;
	case DBUS_DOUBLE: *c = 'd'; return 0;
	case DBUS_ARRAY: *c = 'a'; return 0;
	case DBUS_VARIANT: *c = 'v'; return 0;
	case DBUS_STRUCT_BEGIN: *c = '('; return 0;
	case DBUS_STRUCT_END: *c = ')'; return 0;
	case DBUS_DICT_BEGIN: *c = '{'; return 0;
	case DBUS_DICT_END: *c = '}'; return 0;
	default: return -1;
	}
}

static uint8_t get_sig_len(const dbus_sig *signature)
{
	int i = 0;
	for (i = 0; i < 256 && signature->a[i] != -1; i++)
		;
	return i;
}

static int put_signature(struct dbus_writer *writer, const dbus_sig *signature)
{
	int r = 0, i;
	uint8_t len = get_sig_len(signature);
	r |= put_w8(writer, len);
	if (r) return r;
	for (i = 0; i < len; i++) {
		char c = -1;
		r |= char_of_sig_elem(signature->a[i], &c);
		r |= put_w8(writer, (uint8_t) c);
		if (r) break;
	}
	r |= put_w8(writer, 0);
	return r;
}

static int get_signature(struct dbus_reader *reader, dbus_sig *signature)
{
	int i, r = 0;
	uint8_t len;

	r |= get_w8(reader, &len);
	if (r) return r;

	check_read(len);
	for (i = 0; i < len; i++) {
		uint8_t t;
		dbus_type se = -1;

		r |= get_w8(reader, &t);
		r |= sig_elem_of_char(t, &se);
		if (r) break;
		signature->a[i] = se;
	}
	r |= get_w8(reader, NULL);
	signature->a[i] = -1;
	return r;
}

static int get_variant(struct dbus_reader *reader, dbus_sig *signature)
{
	return get_signature(reader, signature);
}

static int put_variant(struct dbus_writer *writer, const dbus_sig *signature)
{
	return put_signature(writer, signature);
}

/****************************************************************************/
/* medium level */
static int read_header(struct dbus_reader *reader, struct header *header)
{
	uint8_t endianness;
	int r = 0;

	memset(header, '\0', sizeof(struct header));

	r |= get_w8(reader, &endianness);
	r |= get_w8(reader, &header->messagetype);
	r |= get_w8(reader, &header->flags);
	r |= get_w8(reader, &header->ver);

	header->endianness = (endianness == 'l') ? 0 : 1;
	reader->endianness = header->endianness;

	r |= get_w32(reader, &header->bodylen);
	r |= get_w32(reader, &header->serial);
	r |= get_w32(reader, &header->fieldslen);

	return r;
}

static int read_headerfields(struct dbus_reader *reader, int length, dbus_msg *msg)
{
	int r = 0;
	uint8_t ty;
	dbus_sig signature;

#define assertskip(FT, T) if (signature.a[0] != T) { printf("assert failure: on field %d: expecting %d received %d\n", FT, T, signature.a[0]); continue; }

	while (reader->offset < length) {
		r |= get_w8(reader, &ty);
		if (r) break;
		r |= get_variant(reader, &signature);
		if (r) break;
		switch (ty) {
		case DBUS_FIELD_PATH:
			assertskip(ty, DBUS_OBJECTPATH);
			r |= get_string(reader, &msg->path);
			break;
		case DBUS_FIELD_INTERFACE:
			assertskip(ty, DBUS_STRING);
			r |= get_string(reader, &msg->interface);
			break;
		case DBUS_FIELD_MEMBER:
			assertskip(ty, DBUS_STRING);
			r |= get_string(reader, &msg->method);
			break;
		case DBUS_FIELD_ERROR_NAME:
			assertskip(ty, DBUS_STRING);
			r |= get_string(reader, &msg->error_name);
			break;
		case DBUS_FIELD_REPLY_SERIAL:
			assertskip(ty, DBUS_UINT32);
			r |= get_w32(reader, &msg->reply_serial);
			break;
		case DBUS_FIELD_DESTINATION:
			assertskip(ty, DBUS_STRING);
			r |= get_string(reader, &msg->destination);
			break;
		case DBUS_FIELD_SENDER:
			assertskip(ty, DBUS_STRING);
			r |= get_string(reader, &msg->sender);
			break;
		case DBUS_FIELD_SIGNATURE:
			assertskip(ty, DBUS_SIGNATURE);
			r |= get_signature(reader, &msg->signature);
			break;
		case DBUS_FIELD_UNIX_FDS:
			break;
		default:
			printf("unknown type: %d\n", ty);
			return 3;
		}
		if (r) break;
		r |= align_read(reader, 8);
		if (r) break;
	}
	return r;
}

void dbus_msg_free(dbus_msg *msg)
{
	free(msg->destination);
	free(msg->path);
	free(msg->interface);
	free(msg->method);
	free(msg->error_name);
	free(msg->sender);
	free(msg->reader.data);
	memset(msg, '\0', sizeof(dbus_msg));
	free(msg);
}

dbus_msg *dbus_msg_new(uint32_t serial)
{
	dbus_msg *msg = malloc(sizeof(dbus_msg));
	if (msg) {
		memset(msg, '\0', sizeof(dbus_msg));

		msg->writer.buffer = NULL;
		msg->writer.length = 0;

		msg->reader.data = NULL;
		msg->reader.length = 0;

		msg->signature.a[0] = -1;
		msg->serial = serial;
	}
	return msg;
}

int dbus_msg_body_add(dbus_msg *msg, uint32_t length)
{
	msg->writer.buffer = malloc(length);
	if (!msg->writer.buffer)
		return -1;
	msg->writer.length = length;
	msg->writer.offset = 0;
	return 0;
}

dbus_msg *dbus_msg_new_method_call(uint32_t serial,
                                   const char *destination, const char *path,
                                   const char *interface, const char *method)
{
	dbus_msg *msg = dbus_msg_new(serial);
	if (msg) {
		msg->type = DBUS_TYPE_METHOD_CALL;
		msg->destination = strdup(destination);
		msg->path = strdup(path);
		msg->interface = strdup(interface);
		msg->method = strdup(method);
		if (!(msg->destination && msg->path && msg->interface && msg->method)) {
			free(msg->destination);
			free(msg->path);
			free(msg->interface);
			free(msg->method);
			free(msg);
			return NULL;
		}
	}
	return msg;
}

void dbus_msg_set_signature(dbus_msg *msg, dbus_sig *signature)
{
	int i;
	for (i = 0; i < 256; i++)
		msg->signature.a[i] = -1;
	for (i = 0; i < 256 && signature->a[i] != -1; i++)
		msg->signature.a[i] = signature->a[i];
}

#define ACCESSOR_STRING_SET(ty) \
	void dbus_msg_set_##ty(dbus_msg *msg, const char *val) { msg->ty = strdup(val); }

ACCESSOR_STRING_SET(path)
ACCESSOR_STRING_SET(destination)
ACCESSOR_STRING_SET(interface)
ACCESSOR_STRING_SET(error_name)
ACCESSOR_STRING_SET(method)
ACCESSOR_STRING_SET(sender)

/* adding body method */
int dbus_msg_body_add_byte(dbus_msg *msg, uint8_t val) { return put_w8(&msg->writer, val); }
int dbus_msg_body_add_boolean(dbus_msg *msg, bool val) { return put_w32(&msg->writer, val ? 1 : 0); }
int dbus_msg_body_add_int16(dbus_msg *msg, int16_t val) { return put_w16(&msg->writer, (uint16_t) val); }
int dbus_msg_body_add_uint16(dbus_msg *msg, uint16_t val) { return put_w16(&msg->writer, val); }
int dbus_msg_body_add_int32(dbus_msg *msg, int32_t val) { return put_w32(&msg->writer, (uint32_t) val); }
int dbus_msg_body_add_uint32(dbus_msg *msg, uint32_t val) { return put_w32(&msg->writer, val); }
int dbus_msg_body_add_int64(dbus_msg *msg, int64_t val) { return put_w64(&msg->writer, (uint64_t) val); }
int dbus_msg_body_add_uint64(dbus_msg *msg, uint64_t val) { return put_w64(&msg->writer, val); }
int dbus_msg_body_add_double(dbus_msg *msg, double val) { return put_w64(&msg->writer, /* FIXME */ (uint64_t) val); }
int dbus_msg_body_add_string(dbus_msg *msg, const char *val) { return put_string(&msg->writer, val, strlen(val)); }
int dbus_msg_body_add_object_path(dbus_msg *msg, const char *val) { return dbus_msg_body_add_string(msg, val); }
int dbus_msg_body_add_structure(dbus_msg *msg) { return align_write(&msg->writer, 8); }
int dbus_msg_body_add_variant(dbus_msg *msg, dbus_sig *signature) { return put_variant(&msg->writer, signature); }
int dbus_msg_body_add_array_begin(dbus_msg *msg, dbus_type element, dbus_array_writer *aw)
{
	int r = 0;
	r |= put_var_w32(&msg->writer, &aw->ptr);
	if (r) return r;
	r |= align_write(&msg->writer, alignment_of_type(element));
	if (r) return r;
	aw->offset = msg->writer.offset;
	return r;
}

int dbus_msg_body_add_array_end(dbus_msg *msg, dbus_array_writer *aw)
{
	uint32_t len = msg->writer.offset - aw->offset;
	*(aw->ptr) = (msg->writer.endianness) ? swap32(len) : len;
	return 0;
}

/* getting body method */
int dbus_msg_body_get_byte(dbus_msg *msg, uint8_t *val) { return get_w8(&msg->reader, val); }
int dbus_msg_body_get_boolean(dbus_msg *msg, bool *val) { uint32_t v; int r = get_w32(&msg->reader, &v); *val = v; return r; }
int dbus_msg_body_get_int16(dbus_msg *msg, int16_t *val) { return get_w16(&msg->reader, (uint16_t *) val); }
int dbus_msg_body_get_uint16(dbus_msg *msg, uint16_t *val) { return get_w16(&msg->reader, val); }
int dbus_msg_body_get_int32(dbus_msg *msg, int32_t *val) { return get_w32(&msg->reader, (uint32_t *) val); }
int dbus_msg_body_get_uint32(dbus_msg *msg, uint32_t *val) { return get_w32(&msg->reader, val); }
int dbus_msg_body_get_int64(dbus_msg *msg, int64_t *val) { return get_w64(&msg->reader, (uint64_t *) val); }
int dbus_msg_body_get_uint64(dbus_msg *msg, uint64_t *val) { return get_w64(&msg->reader, val); }
int dbus_msg_body_get_double(dbus_msg *msg, double *val) { return get_w64(&msg->reader, (uint64_t *) val); }
int dbus_msg_body_get_string(dbus_msg *msg, char **val) { return get_string(&msg->reader, val); }
int dbus_msg_body_get_object_path(dbus_msg *msg, char **val) { return dbus_msg_body_get_string(msg, val); }
int dbus_msg_body_get_structure(dbus_msg *msg) { return align_read(&msg->reader, 8); }
int dbus_msg_body_get_variant(dbus_msg *msg, dbus_sig *signature) { return get_variant(&msg->reader, signature); }

int dbus_msg_body_get_array(dbus_msg *msg, dbus_type element, dbus_array_reader *ar)
{
	int r = 0;

	r |= get_w32(&msg->reader, &ar->length);
	if (r) return r;
	r |= align_read(&msg->reader, alignment_of_type(element));
	if (r) return r;
	ar->offset = msg->reader.offset;
	return r;
}

int dbus_msg_body_get_array_left(dbus_msg *msg, dbus_array_reader *ar)
{
	return ar->length - (msg->reader.offset - ar->offset);
}

int dbus_msg_marshall(dbus_msg *msg, struct dbus_writer *writer)
{
	uint32_t *fieldlength = NULL;
	int r = 0;
	dbus_sig signature;

	r |= put_w8(writer, 'l');
	r |= put_w8(writer, msg->type);
	r |= put_w8(writer, 0); /* flags */
	r |= put_w8(writer, 1); /* VER */
	r |= put_w32(writer, msg->writer.offset); /* body length */
	r |= put_w32(writer, msg->serial);

	r |= put_var_w32(writer, &fieldlength);

#define PUT_HDRFIELD(FIELD,SIG)	do { \
					signature.a[0] = SIG; signature.a[1] = -1; \
					r |= align_write(writer, 8); \
					r |= put_w8(writer, FIELD); \
					r |= put_variant(writer, &signature); \
				} while (0)

	if (msg->path) {
		PUT_HDRFIELD(DBUS_FIELD_PATH, DBUS_OBJECTPATH);
		r |= put_string(writer, msg->path, strlen(msg->path));
	}
	if (msg->destination) {
		PUT_HDRFIELD(DBUS_FIELD_DESTINATION, DBUS_STRING);
		r |= put_string(writer, msg->destination, strlen(msg->destination));
	}
	if (msg->interface) {
		PUT_HDRFIELD(DBUS_FIELD_INTERFACE, DBUS_STRING);
		r |= put_string(writer, msg->interface, strlen(msg->interface));
	}
	if (msg->error_name) {
		PUT_HDRFIELD(DBUS_FIELD_ERROR_NAME, DBUS_STRING);
		r |= put_string(writer, msg->error_name, strlen(msg->error_name));
	}
	if (msg->reply_serial) {
		PUT_HDRFIELD(DBUS_FIELD_REPLY_SERIAL, DBUS_UINT32);
		r |= put_w32(writer, msg->reply_serial);
	}
	if (msg->sender) {
		PUT_HDRFIELD(DBUS_FIELD_SENDER, DBUS_STRING);
		r |= put_string(writer, msg->sender, strlen(msg->sender));
	}
	if (msg->method) {
		PUT_HDRFIELD(DBUS_FIELD_MEMBER, DBUS_STRING);
		r |= put_string(writer, msg->method, strlen(msg->method));
	}
	if (get_sig_len(&msg->signature) > 0) {
		PUT_HDRFIELD(DBUS_FIELD_SIGNATURE, DBUS_SIGNATURE);
		r |= put_signature(writer, &msg->signature);
	}
	if (!r) {
		uint32_t v = writer->offset - 16;
		*fieldlength = (writer->endianness) ? swap32(v) : v;
	}
	align_write(writer, 8);
	return r;
}

int dbus_msg_send(dbus_io *dio, dbus_msg *msg)
{
	int r = 0;
	uint8_t header[1024];
	struct dbus_writer writer;

	memset(&writer, '\0', sizeof(struct dbus_writer));
	writer.buffer = header;
	writer.length = 1024;

	dbus_msg_marshall(msg, &writer);

	r |= dio->io_write(dio->priv, header, writer.offset);
	if (r == 0 && msg->writer.offset > 0)
		r |= dio->io_write(dio->priv, msg->writer.buffer, msg->writer.offset);
	return r;
}

int dbus_msg_recv(dbus_io *dio, dbus_msg **rmsg)
{
	uint8_t headerdata[16];
	struct header header;
	struct dbus_reader reader;
	dbus_msg *msg;
	int r = 0, toread;

	memset(&reader, '\0', sizeof(struct dbus_reader));

	/* read header */
	r |= dio->io_read(dio->priv, headerdata, 16);
	if (r) {
		dio_debug(dio, "reading header failed");
		return -1;
	}
	reader_initialize(&reader, 0, 16);
	reader.data = headerdata;
	r |= read_header(&reader, &header);

	/* read header fields */
	toread = ALIGN_VALUE(header.fieldslen, 8);

	reader.data = calloc(toread, sizeof(char));
	if (!reader.data) {
		dio_debug(dio, "calloc failed");
		return -3;
	}
	r |= dio->io_read(dio->priv, reader.data, toread);
	if (r) {
		dio_debug(dio, "reading body failed");
		return -1;
	}

	msg = dbus_msg_new(header.serial);
	if (!msg) {
		free(reader.data);
		dio_debug(dio, "allocating message failed");
		return -4;
	}
	msg->type = header.messagetype;

	reader_initialize(&reader, 16, toread);
	r |= read_headerfields(&reader, header.fieldslen, msg);
	free(reader.data);

	/* read body */
	msg->reader.data = calloc(header.bodylen, sizeof(char));
	if (!msg->reader.data) {
		dio_debug(dio, "cannot allocate reader buffer");
		dbus_msg_free(msg);
		return -5;
	}

	r |= dio->io_read(dio->priv, msg->reader.data, header.bodylen);
	reader_initialize(&msg->reader, 0, header.bodylen);
	if (!r)
		*rmsg = msg;
	return r;
}

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

static int connect_unix_socket(char *path, int abstract, int length)
{
#ifdef HAVE_UNIX_SOCKET
	struct sockaddr_un addr;
	int sock;

	addr.sun_family = AF_UNIX;
	if (abstract) {
		addr.sun_path[0] = '\0';
		strcpy(addr.sun_path + 1, path);
	} else {
		strcpy(addr.sun_path, path);
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		printf("couldn't create a unix socket\n");
		return -1;
	}
	if (connect(sock, (const struct sockaddr *) &addr, length + (abstract ? 1 : 0) + 2)) {
		perror("connect failure\n");
		return -1;
	}
	return sock;
#else
	return -1;
#endif
}

int dbus_connect_session(void)
{
	char *session_address = getenv("DBUS_SESSION_BUS_ADDRESS");
	if (!session_address) {
		return -1;
	}
	if (strncmp("unix:", session_address, 5) == 0) {
		char abstract[128];
		char *flags = session_address + 5;

		memset(abstract, '\0', 128);
		for (; *flags != '\0'; ) {
			char *end, *flagval;

			end = strchr(flags, ',');
			if (!end)
				end = flags + strlen(flags);

			if (strncmp("abstract=", flags, 9) == 0) {
				flagval = flags + 9;
				strncpy(abstract, flagval, end - flagval);
			}

			if (*end != ',')
				break;
			flags = end + 1;
		}
		return connect_unix_socket(abstract, 1, strlen(abstract));
	}
	return -1;
}

int dbus_connect_system(void)
{
	char system[] = "/var/run/dbus/system_bus_socket";
	return connect_unix_socket(system, 0, strlen(system));
}

int dbus_auth(dbus_io *dio, char *auth)
{
	char buf[256];
	int len;
	int r = 0;

	len = sprintf(buf, "%cAUTH %s\r\n", '\0', auth);
	r = dio->io_write(dio->priv, buf, len);
	if (r)
		return r;

	r = read_line(dio, buf, 256);
	if (r)
		return r;
	r = dio->io_write(dio->priv, "BEGIN\r\n", 7);
	return r;
}
