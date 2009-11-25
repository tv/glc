/**
 * \file glc/core/stream.c
 * \brief stream io
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007-2008
 * For conditions of distribution and use, see copyright notice in glc.h
 */

/**
 * \addtogroup stream
 *  \{
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <packetstream.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <glc/common/glc.h>
#include <glc/common/state.h>
#include <glc/common/core.h>
#include <glc/common/log.h>
#include <glc/common/thread.h>
#include <glc/common/util.h>

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glc/core/tracker.h>

#include "stream.h"

#define STREAM_READING       0x1
#define STREAM_WRITING       0x2
#define STREAM_RUNNING       0x4
#define STREAM_INFO_WRITTEN  0x8
#define STREAM_INFO_READ    0x10
#define STREAM_INFO_VALID   0x20

// #define PORT 13373
// #define DEST_ADDR "127.0.0.1"

struct stream_s {
	glc_t *glc;
	glc_flags_t flags;
	glc_thread_t thread;
	int sockfd;
	int sync;
	struct sockaddr_in addr;
	u_int32_t stream_version;
	callback_request_func_t callback;
	tracker_t state_tracker;
};

void stream_finish_callback(void *ptr, int err);
int stream_read_callback(glc_thread_state_t *state);
int stream_write_message(stream_t stream, glc_message_header_t *header, void *message, size_t message_size);
int stream_write_state_callback(glc_message_header_t *header, void *message, size_t message_size, void *arg);

int stream_init(stream_t *stream, glc_t *glc)
{
	*stream = malloc(sizeof(struct stream_s));
	memset(*stream, 0, sizeof(struct stream_s));

	(*stream)->glc = glc;
	(*stream)->sockfd = -1;
	(*stream)->sync = 0;

	(*stream)->thread.flags = GLC_THREAD_READ;
	(*stream)->thread.ptr = *stream;
	(*stream)->thread.read_callback = &stream_read_callback;
	(*stream)->thread.finish_callback = &stream_finish_callback;
	(*stream)->thread.threads = 1;

	tracker_init(&(*stream)->state_tracker, (*stream)->glc);

	return 0;
}

int stream_destroy(stream_t stream)
{
	tracker_destroy(stream->state_tracker);
	free(stream);
	return 0;
}

int stream_set_sync(stream_t stream, int sync)
{
	stream->sync = sync;
	return 0;
}

int stream_set_callback(stream_t stream, callback_request_func_t callback)
{
	stream->callback = callback;
	return 0;
}

int stream_open_target(stream_t stream, const char *host, int port)
{
	int sockfd=0, ret = 0;
	if (stream->sockfd >= 0)
		return EBUSY;

	glc_log(stream->glc, GLC_INFORMATION, "stream",
		 "opening %s:%d for writing stream (%s)",
		 host, port,
		 stream->sync ? "sync" : "no sync");

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd == -1) {
		glc_log(stream->glc, GLC_ERROR, "stream", "can't open %s: %s (%d)",
			host, strerror(errno), errno);
		return errno;
	}

	// if((setsockopt(sockfd,SOL_SOCKET,SO_BROADCAST, &broadcast,sizeof broadcast)) == -1)
	// {
	// 	glc_log(stream->glc, GLC_ERROR, "stream", "can't open %s: %s (%d)",
	// 		filename, strerror(errno), errno);
	// 	return errno;
	// }

	stream->addr.sin_family = AF_INET;
	stream->addr.sin_port = htons(port);
	inet_aton(host, &stream->addr.sin_addr);
	memset(stream->addr.sin_zero,'\0',sizeof(stream->addr.sin_zero));

	connect(sockfd, (struct sockaddr*)&stream->addr, sizeof(stream->addr));

	if ((ret = stream_set_target(stream, sockfd)))
		close(sockfd);

	return ret;
}

int stream_set_target(stream_t stream, int sockfd)
{
	if (stream->sockfd >= 0)
		return EBUSY;

	if (flock(sockfd, LOCK_EX | LOCK_NB) == -1) {
		glc_log(stream->glc, GLC_ERROR, "stream",
			 "can't lock stream: %s (%d)", strerror(errno), errno);
		return errno;
	}

	/* truncate file when we have locked it */
	//lseek(stream->sockfd, 0, SEEK_SET);
	//ftruncate(stream->sockfd, 0);

	stream->sockfd = sockfd;
	stream->flags |= STREAM_WRITING;
	return 0;
}

int stream_close_target(stream_t stream)
{
	if ((stream->sockfd < 0) | (stream->flags & STREAM_RUNNING) |
	    (!(stream->flags & STREAM_WRITING)))
		return EAGAIN;

	/* try to remove lock */
	if (flock(stream->sockfd, LOCK_UN) == -1)
		glc_log(stream->glc, GLC_WARNING,
			 "stream", "can't unlock stream: %s (%d)",
			 strerror(errno), errno);

	if (close(stream->sockfd))
		glc_log(stream->glc, GLC_ERROR, "stream",
			 "can't close stream: %s (%d)",
			 strerror(errno), errno);

	stream->sockfd = -1;
	stream->flags &= ~(STREAM_RUNNING | STREAM_WRITING | STREAM_INFO_WRITTEN);

	return 0;
}

int stream_write_info(stream_t stream, glc_stream_info_t *info,
		    const char *info_name, const char *info_date)
{
	if ((stream->sockfd < 0) | (stream->flags & STREAM_RUNNING) |
	    (!(stream->flags & STREAM_WRITING)))
		return EAGAIN;

	if (send(stream->sockfd, info, sizeof(glc_stream_info_t),0 ) != sizeof(glc_stream_info_t))
		goto err;
	if (send(stream->sockfd, info_name, info->name_size, 0) != info->name_size)
		goto err;
	if (send(stream->sockfd, info_date, info->date_size, 0) != info->date_size)
		goto err;

	stream->flags |= STREAM_INFO_WRITTEN;
	return 0;
err:
	glc_log(stream->glc, GLC_ERROR, "stream",
		 "can't write stream information: %s (%d)",
		 strerror(errno), errno);
	return errno;
}

int stream_write_message(stream_t stream, glc_message_header_t *header, void *message, size_t message_size)
{
	glc_size_t glc_size = (glc_size_t) message_size;

	if (send(stream->sockfd, &glc_size, sizeof(glc_size_t), 0) != sizeof(glc_size_t))
		goto err;
	if (send(stream->sockfd, header, sizeof(glc_message_header_t), 0) != sizeof(glc_message_header_t))
		goto err;
	if (message_size > 0) {
		if (send(stream->sockfd, message, message_size, 0) != message_size)
			goto err;
	}

	return 0;
err:
	return errno;
}

int stream_write_eof(stream_t stream)
{
	int ret;
	glc_message_header_t hdr;
	hdr.type = GLC_MESSAGE_CLOSE;

	if ((stream->sockfd < 0) | (stream->flags & STREAM_RUNNING) |
	    (!(stream->flags & STREAM_WRITING))) {
	    ret = EAGAIN;
	    goto err;
	}

	if ((ret = stream_write_message(stream, &hdr, NULL, 0)))
		goto err;

	return 0;
err:
	glc_log(stream->glc, GLC_ERROR, "stream",
		 "can't write eof: %s (%d)",
		 strerror(ret), ret);
	return ret;
}

int stream_write_state_callback(glc_message_header_t *header, void *message, size_t message_size, void *arg)
{
	stream_t stream = arg;
	return stream_write_message(stream, header, message, message_size);
}

int stream_write_state(stream_t stream)
{
	int ret;
	if ((stream->sockfd < 0) | (stream->flags & STREAM_RUNNING) |
	    (!(stream->flags & STREAM_WRITING))) {
	    ret = EAGAIN;
	    goto err;
	}

	if ((ret = tracker_iterate_state(stream->state_tracker, &stream_write_state_callback, stream)))
		goto err;

	return 0;
err:
	glc_log(stream->glc, GLC_ERROR, "stream",
		 "can't write state: %s (%d)",
		 strerror(ret), ret);
	return ret;
}

int stream_write_process_start(stream_t stream, ps_buffer_t *from)
{
	int ret;
	if ((stream->sockfd < 0) | (stream->flags & STREAM_RUNNING) |
	    (!(stream->flags & STREAM_WRITING)) |
	    (!(stream->flags & STREAM_INFO_WRITTEN)))
		return EAGAIN;

	if ((ret = glc_thread_create(stream->glc, &stream->thread, from, NULL)))
		return ret;
	/** \todo cancel buffer if this fails? */
	stream->flags |= STREAM_RUNNING;

	return 0;
}

int stream_write_process_wait(stream_t stream)
{
	if ((stream->sockfd < 0) | (!(stream->flags & STREAM_RUNNING)) |
	    (!(stream->flags & STREAM_WRITING)) |
	    (!(stream->flags & STREAM_INFO_WRITTEN)))
		return EAGAIN;

	glc_thread_wait(&stream->thread);
	stream->flags &= ~(STREAM_RUNNING | STREAM_INFO_WRITTEN);

	return 0;
}

void stream_finish_callback(void *ptr, int err)
{
	stream_t stream = (stream_t) ptr;

	if (err)
		glc_log(stream->glc, GLC_ERROR, "stream", "%s (%d)", strerror(err), err);
}

int stream_read_callback(glc_thread_state_t *state)
{
	stream_t stream = (stream_t) state->ptr;
	glc_container_message_header_t *container;
	glc_size_t glc_size;
	glc_callback_request_t *callback_req;

	/* let state tracker to process this message */
	tracker_submit(stream->state_tracker, &state->header, state->read_data, state->read_size);

	if (state->header.type == GLC_CALLBACK_REQUEST) {
		/* callback request messages are never written to disk */
		if (stream->callback != NULL) {
			/* callbacks may manipulate target file so remove STREAM_RUNNING flag */
			stream->flags &= ~STREAM_RUNNING;
			callback_req = (glc_callback_request_t *) state->read_data;
			stream->callback(callback_req->arg);
			stream->flags |= STREAM_RUNNING;
		}
	} else if (state->header.type == GLC_MESSAGE_CONTAINER) {
		container = (glc_container_message_header_t *) state->read_data;
		if (write(stream->sockfd, state->read_data, sizeof(glc_container_message_header_t) + container->size)
		    != (sizeof(glc_container_message_header_t) + container->size))
			goto err;
	} else {
		/* emulate container message */
		glc_size = state->read_size;
		if (write(stream->sockfd, &glc_size, sizeof(glc_size_t)) != sizeof(glc_size_t))
			goto err;
		if (write(stream->sockfd, &state->header, sizeof(glc_message_header_t))
		    != sizeof(glc_message_header_t))
			goto err;
		if (write(stream->sockfd, state->read_data, state->read_size) != state->read_size)
			goto err;
	}

	return 0;

err:
	glc_log(stream->glc, GLC_ERROR, "stream", "%s (%d)", strerror(errno), errno);
	return errno;
}

int stream_test_stream_version(u_int32_t version)
{
	/* current version is always supported */
	if (version == GLC_STREAM_VERSION) {
		return 0;
	} else if (version == 0x03) {
		/*
		 0.5.5 was last version to use 0x03.
		 Only change between 0x03 and 0x04 is header and
		 size order in on-disk packet header.
		*/
		return 0;
	}
	return ENOTSUP;
}

/**  \} */
