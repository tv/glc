/**
 * \file hook/main.c
 * \brief main wrapper library
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007-2008
 * For conditions of distribution and use, see copyright notice in glc.h
 */

/**
 * \addtogroup hook
 *  \{
 * \defgroup main main wrapper library
 *  \{
 */

#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <elfhacks.h>
#include <unistd.h>
#include <signal.h>
#include <fnmatch.h>
#include <sched.h>
#include <pthread.h>

#include <glc/common/glc.h>
#include <glc/common/core.h>
#include <glc/common/log.h>
#include <glc/common/util.h>
#include <glc/common/state.h>
#include <glc/core/pack.h>
#include <glc/core/file.h>
#include <glc/core/stream.h>

#include "lib.h"

#define MAIN_COMPRESS_NONE         0x2
#define MAIN_COMPRESS_QUICKLZ      0x4
#define MAIN_COMPRESS_LZO          0x8
#define MAIN_CUSTOM_LOG           0x10
#define MAIN_SYNC                 0x20
#define MAIN_COMPRESS_LZJB        0x40
#define MAIN_START                0x80

struct main_private_s {
	glc_t glc;
	glc_flags_t flags;

	ps_buffer_t *uncompressed;
	ps_buffer_t *compressed;
	size_t uncompressed_size, compressed_size;

	file_t file;
	stream_t stream;
	pack_t pack;

	unsigned int capture;
	const char *stream_file_fmt;
	char *stream_file;

	char *stream_host;
	int   stream_port;

	int sighandler;
	void (*sigint_handler)(int);
	void (*sighup_handler)(int);
	void (*sigterm_handler)(int);

	glc_utime_t stop_time;
};

__PRIVATE glc_lib_t lib = {NULL, /* dlopen */
			   NULL, /* dlsym */
			   NULL, /* dlvsym */
			   NULL, /* __libc_dlsym */
			   0, /* initialized */
			   0, /* running */
			   PTHREAD_MUTEX_INITIALIZER, /* init_lock */
			   0, /* flags */
			   };
__PRIVATE struct main_private_s mpriv;

__PRIVATE int init_buffers();
__PRIVATE void lib_close();
__PRIVATE int load_environ();
__PRIVATE void signal_handler(int signum);
__PRIVATE void get_real_libc_dlsym();
__PRIVATE void reload_stream_callback(void *arg);

void init_glc()
{
	struct sigaction new_sighandler, old_sighandler;
	int ret;
	mpriv.flags = 0;
	mpriv.capture = 0;
	mpriv.stop_time = 0;
	mpriv.stream_file = NULL;
	mpriv.stream_file_fmt = "%app%-%pid%-%capture%.glc";
	mpriv.stream_host = NULL;

	if ((ret = pthread_mutex_lock(&lib.init_lock)))
		goto err;

	if (lib.initialized)
		return;

	/* init glc first */
	glc_init(&mpriv.glc);
	/* initialize state */
	glc_state_init(&mpriv.glc);

	load_environ();
	glc_util_log_version(&mpriv.glc);

	if ((ret = init_buffers()))
		goto err;

	if ((ret = opengl_init(&mpriv.glc)))
		goto err;
	if ((ret = alsa_init(&mpriv.glc)))
		goto err;
	if ((ret = x11_init(&mpriv.glc)))
		goto err;

	/* get current time for correct timediff */
	mpriv.stop_time = glc_state_time(&mpriv.glc);

	glc_util_log_info(&mpriv.glc);

	lib.initialized = 1; /* we've technically done */

	if (mpriv.flags & MAIN_START)
		start_capture();

	atexit(lib_close);

	/** \todo hook sigaction() ? */
	if (mpriv.sighandler) {
		glc_log(&mpriv.glc, GLC_INFORMATION, "main",
			 "setting signal handler");

		new_sighandler.sa_handler = signal_handler;
		sigemptyset(&new_sighandler.sa_mask);
		new_sighandler.sa_flags = 0;

		sigaction(SIGINT, &new_sighandler, &old_sighandler);
		mpriv.sigint_handler = old_sighandler.sa_handler;

		sigaction(SIGHUP, &new_sighandler, &old_sighandler);
		mpriv.sighup_handler = old_sighandler.sa_handler;

		sigaction(SIGTERM, &new_sighandler, &old_sighandler);
		mpriv.sigterm_handler = old_sighandler.sa_handler;
	}

	if ((ret = pthread_mutex_unlock(&lib.init_lock)))
		goto err;

	glc_log(&mpriv.glc, GLC_INFORMATION, "main", "glc initialized");
	glc_log(&mpriv.glc, GLC_DEBUG, "main", "LD_PRELOAD=%s", getenv("LD_PRELOAD"));
	return;
err:
	fprintf(stderr, "(glc) %s (%d)\n", strerror(ret), ret);
	exit(ret); /* glc initialization is critical */
}

int init_buffers()
{
	int ret;
	ps_bufferattr_t attr;
	ps_bufferattr_init(&attr);

	ps_bufferattr_setsize(&attr, mpriv.uncompressed_size);
	mpriv.uncompressed = (ps_buffer_t *) malloc(sizeof(ps_buffer_t));
	if ((ret = ps_buffer_init(mpriv.uncompressed, &attr)))
		return ret;

	if (!(mpriv.flags & MAIN_COMPRESS_NONE)) {
		ps_bufferattr_setsize(&attr, mpriv.compressed_size);
		mpriv.compressed = (ps_buffer_t *) malloc(sizeof(ps_buffer_t));
		if ((ret = ps_buffer_init(mpriv.compressed, &attr)))
			return ret;
	}

	ps_bufferattr_destroy(&attr);
	return 0;
}

int open_stream()
{
	glc_stream_info_t *stream_info;
	char *info_name, *info_date;
	int ret;

	glc_util_info_create(&mpriv.glc, &stream_info, &info_name, &info_date);

	if(strstr(mpriv.stream_file_fmt, "udp://"))
	{
	    mpriv.stream_host = malloc(15*sizeof(char));

        glc_util_format_stream(mpriv.stream_file_fmt, mpriv.stream_host, &mpriv.stream_port);
        printf("\n--> %s\n\n",mpriv.stream_host);

        if ((ret = stream_set_sync(mpriv.stream, (mpriv.flags & MAIN_SYNC) ? 1 : 0)))
            return ret;
        if ((ret = stream_open_target(mpriv.stream, mpriv.stream_host, mpriv.stream_port)))
            return ret;
        if ((ret = stream_write_info(mpriv.stream, stream_info, info_name, info_date)))
            return ret;

	} else {
        mpriv.stream_file = glc_util_format_filename(mpriv.stream_file_fmt, mpriv.capture);

        if ((ret = file_set_sync(mpriv.file, (mpriv.flags & MAIN_SYNC) ? 1 : 0)))
            return ret;
        if ((ret = file_open_target(mpriv.file, mpriv.stream_file)))
            return ret;
        if ((ret = file_write_info(mpriv.file, stream_info, info_name, info_date)))
            return ret;
	}
	free(stream_info);
	free(info_name);
	free(info_date);

	return 0;
}

int close_stream()
{
	int ret;

	if (mpriv.stream_file != NULL) {
		free(mpriv.stream_file);
		mpriv.stream_file = NULL;
	}

	if ((ret = file_close_target(mpriv.file)))
		return ret;

	return 0;
}

void reload_stream_callback(void *arg)
{
	/* this is called when callback request arrives to file object */
	int ret;

	glc_log(&mpriv.glc, GLC_INFORMATION, "main", "reloading stream");

	if ((ret = file_write_eof(mpriv.file)))
		goto err;
	if ((ret = close_stream()))
		goto err;
	if ((ret = open_stream()))
		goto err;
	if ((ret = file_write_state(mpriv.file)))
		goto err;

	return;
err:
	glc_log(&mpriv.glc, GLC_ERROR, "main",
		"can't reload stream: %s (%d)\n", strerror(ret), ret);
}

int reload_stream()
{
	glc_message_header_t hdr;
	hdr.type = GLC_CALLBACK_REQUEST;
	glc_callback_request_t callback_req;
	callback_req.arg = NULL;

	/* synchronize with opengl top buffer */
	return opengl_push_message(&hdr, &callback_req, sizeof(glc_callback_request_t));
}

void increment_capture()
{
	mpriv.capture++;
	mpriv.stop_time = 0;
}

int start_capture()
{
	int ret;
	if (lib.flags & LIB_CAPTURING)
		return EAGAIN;

	if (!lib.running) {
		if ((ret = start_glc()))
			goto err;
	}

	if ((ret = alsa_capture_start_all()))
		goto err;
	if ((ret = opengl_capture_start()))
		goto err;

	glc_state_time_add_diff(&mpriv.glc, glc_state_time(&mpriv.glc) - mpriv.stop_time);
	lib.flags |= LIB_CAPTURING;
	glc_log(&mpriv.glc, GLC_INFORMATION, "main", "started capturing");

	return 0;
err:
	glc_log(&mpriv.glc, GLC_ERROR, "main",
		"can't start capturing: %s (%d)", strerror(ret), ret);
	return ret;
}

int stop_capture()
{
	int ret;

	if (!(lib.flags & LIB_CAPTURING))
		return EAGAIN;

	if ((ret = alsa_capture_stop_all()))
		goto err;
	if ((ret = opengl_capture_stop()))
		goto err;

	lib.flags &= ~LIB_CAPTURING;
	mpriv.stop_time = glc_state_time(&mpriv.glc);
	glc_log(&mpriv.glc, GLC_INFORMATION, "main", "stopped capturing");

	return 0;
err:
	glc_log(&mpriv.glc, GLC_ERROR, "main",
		"can't stop capturing: %s (%d)", strerror(ret), ret);
	return ret;
}

int start_glc()
{
	int ret;

	if (lib.running)
		return EINVAL;

	if (!lib.initialized)
		return EAGAIN;

	glc_log(&mpriv.glc, GLC_INFORMATION, "main", "starting glc");

    if(strstr(mpriv.stream_file_fmt, "udp://"))
	{
	    if ((ret = stream_init(&mpriv.stream, &mpriv.glc)))
            return ret;
        /* NOTE at the moment only reload is used as callback */
        if ((ret = stream_set_callback(mpriv.stream, &reload_stream_callback)))
            return ret;
	}else {
        /* initialize file & write stream info */
        if ((ret = file_init(&mpriv.file, &mpriv.glc)))
            return ret;
        /* NOTE at the moment only reload is used as callback */
        if ((ret = file_set_callback(mpriv.file, &reload_stream_callback)))
            return ret;
	}


	if ((ret = open_stream()))
		return ret;

	if (!(mpriv.flags & MAIN_COMPRESS_NONE)) {
	    if(strstr(mpriv.stream_file_fmt, "udp://"))
	    {
            if ((ret = stream_write_process_start(mpriv.stream, mpriv.compressed)))
                return ret;
	    } else {
            if ((ret = file_write_process_start(mpriv.file, mpriv.compressed)))
                return ret;
	    }

		if ((ret = pack_init(&mpriv.pack, &mpriv.glc)))
			return ret;

		if (mpriv.flags & MAIN_COMPRESS_QUICKLZ)
			pack_set_compression(mpriv.pack, PACK_QUICKLZ);
		else if (mpriv.flags & MAIN_COMPRESS_LZO)
			pack_set_compression(mpriv.pack, PACK_LZO);
		else if (mpriv.flags & MAIN_COMPRESS_LZJB)
			pack_set_compression(mpriv.pack, PACK_LZJB);

		if ((ret = pack_process_start(mpriv.pack, mpriv.uncompressed, mpriv.compressed)))
			return ret;
	} else {
	    glc_log(&mpriv.glc, GLC_WARNING, "main", "compression disabled");
	    if(strstr(mpriv.stream_file_fmt, "udp://"))
	    {
            if ((ret = stream_write_process_start(mpriv.stream, mpriv.uncompressed)))
                return ret;
	    } else {
            if ((ret = file_write_process_start(mpriv.file, mpriv.uncompressed)))
                return ret;
	    }
	}

	if ((ret = alsa_start(mpriv.uncompressed)))
		return ret;
	if ((ret = opengl_start(mpriv.uncompressed)))
		return ret;

	lib.running = 1;
	glc_log(&mpriv.glc, GLC_INFORMATION, "main", "glc running");

	return 0;
}

void signal_handler(int signum)
{
	if ((signum == SIGINT) &&
	    (mpriv.sigint_handler == SIG_IGN))
		return;
	else if ((signum == SIGHUP) &&
	         (mpriv.sighup_handler == SIG_IGN))
		return;
	else if ((signum == SIGTERM) &&
	         (mpriv.sigterm_handler == SIG_IGN))
		return;

	if ((signum == SIGINT) &&
	    (mpriv.sigint_handler != SIG_DFL) &&
	    (mpriv.sigint_handler != NULL))
		mpriv.sigint_handler(signum);
	else if ((signum == SIGHUP) &&
	         (mpriv.sighup_handler != SIG_DFL) &&
	         (mpriv.sighup_handler != NULL))
		mpriv.sighup_handler(signum);
	else if ((signum == SIGTERM) &&
	         (mpriv.sigterm_handler != SIG_DFL) &&
	         (mpriv.sigterm_handler != NULL))
		mpriv.sigterm_handler(signum);

	fprintf(stderr, "(glc) got C-c, will now exit...");
	exit(0); /* may cause lots of damage... */
}

void lib_close()
{
	int ret;
	/*
	 There is a small possibility that a capture operation in another
	 thread is still active. This should be called only in exit() or
	 at return from main loop so we choose performance and not safety.

	 Adding a rwlock for all capture operations might inflict a noticeable
	 cost, at least in complexity.
	*/

	glc_log(&mpriv.glc, GLC_INFORMATION, "main", "closing glc");

	if ((ret = alsa_close()))
		goto err;
	if ((ret = opengl_close()))
		goto err;

	if (lib.running) {
		if (!(mpriv.flags & MAIN_COMPRESS_NONE)) {
			pack_process_wait(mpriv.pack);
			pack_destroy(mpriv.pack);
		}
		file_write_process_wait(mpriv.file);
		close_stream();
		file_destroy(mpriv.file);
	}

	if (mpriv.compressed) {
		ps_buffer_destroy(mpriv.compressed);
		free(mpriv.compressed);
	}

	ps_buffer_destroy(mpriv.uncompressed);
	free(mpriv.uncompressed);

	if (mpriv.flags & MAIN_CUSTOM_LOG)
		glc_log_close(&mpriv.glc);

	glc_state_destroy(&mpriv.glc);
	glc_destroy(&mpriv.glc);

	free(mpriv.stream_file);
	return;
err:
	fprintf(stderr, "(glc) cleanup: %s (%d)\n", strerror(ret), ret);
	return;
}

int load_environ()
{
	char *log_file;

	if (getenv("GLC_START")) {
		if (atoi(getenv("GLC_START")))
			mpriv.flags |= MAIN_START;
	}

	if (getenv("GLC_FILE"))
		mpriv.stream_file_fmt = getenv("GLC_FILE");

	if (getenv("GLC_LOG"))
		glc_log_set_level(&mpriv.glc, atoi(getenv("GLC_LOG")));

	if (getenv("GLC_LOG_FILE")) {
		log_file = malloc(1024);
		snprintf(log_file, 1023, getenv("GLC_LOG_FILE"), getpid());
		glc_log_open_file(&mpriv.glc, log_file);
		free(log_file);
		mpriv.flags |= MAIN_CUSTOM_LOG;
	}

	mpriv.sighandler = 0;
	if (getenv("GLC_SIGHANDLER"))
		mpriv.sighandler = atoi(getenv("GLC_SIGHANDLER"));

	if (getenv("GLC_SYNC")) {
		if (atoi(getenv("GLC_SYNC")))
			mpriv.flags |= MAIN_SYNC;
	}

	mpriv.uncompressed_size = 1024 * 1024 * 25;
	if (getenv("GLC_UNCOMPRESSED_BUFFER_SIZE"))
		mpriv.uncompressed_size = atoi(getenv("GLC_UNCOMPRESSED_BUFFER_SIZE")) * 1024 * 1024;

	mpriv.compressed_size = 1024 * 1024 * 50;
	if (getenv("GLC_COMPRESSED_BUFFER_SIZE"))
		mpriv.compressed_size = atoi(getenv("GLC_COMPRESSED_BUFFER_SIZE")) * 1024 * 1024;

	if (getenv("GLC_COMPRESS")) {
		if (!strcmp(getenv("GLC_COMPRESS"), "lzo"))
			mpriv.flags |= MAIN_COMPRESS_LZO;
		else if (!strcmp(getenv("GLC_COMPRESS"), "quicklz"))
			mpriv.flags |= MAIN_COMPRESS_QUICKLZ;
		else if (!strcmp(getenv("GLC_COMPRESS"), "lzjb"))
			mpriv.flags |= MAIN_COMPRESS_LZJB;
		else
			mpriv.flags |= MAIN_COMPRESS_NONE;
	}

	return 0;
}

void get_real_dlsym()
{
	eh_obj_t libdl;

	if (eh_find_obj(&libdl, "*libdl.so*")) {
		fprintf(stderr, "(glc) libdl.so is not present in memory\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlopen", (void *) &lib.dlopen)) {
		fprintf(stderr, "(glc) can't get real dlopen()\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlsym", (void *) &lib.dlsym)) {
		fprintf(stderr, "(glc) can't get real dlsym()\n");
		exit(1);
	}

	if (eh_find_sym(&libdl, "dlvsym", (void *) &lib.dlvsym)) {
		fprintf(stderr, "(glc) can't get real dlvsym()\n");
		exit(1);
	}

	eh_destroy_obj(&libdl);
}

void get_real___libc_dlsym()
{
	eh_obj_t libc;

	if (eh_find_obj(&libc, "*libc.so*")) {
		fprintf(stderr, "(glc) libc.so is not present in memory\n");
		exit(1);
	}

	if (eh_find_sym(&libc, "__libc_dlsym", (void *) &lib.__libc_dlsym)) {
		fprintf(stderr, "(glc) can't get real __libc_dlsym()\n");
		exit(1);
	}

	eh_destroy_obj(&libc);
}

void *wrapped_func(const char *symbol)
{
	if (!strcmp(symbol, "glXGetProcAddressARB"))
		return &__opengl_glXGetProcAddressARB;
	else if (!strcmp(symbol, "glXSwapBuffers"))
		return &__opengl_glXSwapBuffers;
	else if (!strcmp(symbol, "glFinish"))
		return &__opengl_glFinish;
	else if (!strcmp(symbol, "glXCreateWindow"))
		return &__opengl_glXCreateWindow;
	else if (!strcmp(symbol, "snd_pcm_open"))
		return &__alsa_snd_pcm_open;
	else if (!strcmp(symbol, "snd_pcm_close"))
		return &__alsa_snd_pcm_close;
	else if (!strcmp(symbol, "snd_pcm_open_lconf"))
		return &__alsa_snd_pcm_open_lconf;
	else if (!strcmp(symbol, "snd_pcm_hw_params"))
		return &__alsa_snd_pcm_hw_params;
	else if (!strcmp(symbol, "snd_pcm_writei"))
		return &__alsa_snd_pcm_writei;
	else if (!strcmp(symbol, "snd_pcm_writen"))
		return &__alsa_snd_pcm_writen;
	else if (!strcmp(symbol, "snd_pcm_mmap_writei"))
		return &__alsa_snd_pcm_mmap_writei;
	else if (!strcmp(symbol, "snd_pcm_mmap_writen"))
		return &__alsa_snd_pcm_mmap_writen;
	else if (!strcmp(symbol, "snd_pcm_mmap_begin"))
		return &__alsa_snd_pcm_mmap_begin;
	else if (!strcmp(symbol, "snd_pcm_mmap_commit"))
		return &__alsa_snd_pcm_mmap_commit;
	else if (!strcmp(symbol, "XNextEvent"))
		return &__x11_XNextEvent;
	else if (!strcmp(symbol, "XPeekEvent"))
		return &__x11_XPeekEvent;
	else if (!strcmp(symbol, "XWindowEvent"))
		return &__x11_XWindowEvent;
	else if (!strcmp(symbol, "XMaskEvent"))
		return &__x11_XMaskEvent;
	else if (!strcmp(symbol, "XCheckWindowEvent"))
		return &__x11_XCheckWindowEvent;
	else if (!strcmp(symbol, "XCheckMaskEvent"))
		return &__x11_XCheckMaskEvent;
	else if (!strcmp(symbol, "XCheckTypedEvent"))
		return &__x11_XCheckTypedEvent;
	else if (!strcmp(symbol, "XCheckTypedWindowEvent"))
		return &__x11_XCheckTypedWindowEvent;
	else if (!strcmp(symbol, "XIfEvent"))
		return &__x11_XIfEvent;
	else if (!strcmp(symbol, "XCheckIfEvent"))
		return &__x11_XCheckIfEvent;
	else if (!strcmp(symbol, "XPeekIfEvent"))
		return &__x11_XPeekIfEvent;
	else if (!strcmp(symbol, "XF86VidModeSetGamma"))
		return &__x11_XF86VidModeSetGamma;
	else if (!strcmp(symbol, "dlopen"))
		return &__main_dlopen;
	else if (!strcmp(symbol, "dlsym"))
		return &__main_dlsym;
	else if (!strcmp(symbol, "dlvsym"))
		return &__main_dlvsym;
	else if (!strcmp(symbol, "__libc_dlsym"))
		return &__main___libc_dlsym;
	else
		return NULL;
}

__PUBLIC void *dlopen(const char *filename, int flag)
{
	return __main_dlopen(filename, flag);
}

void *__main_dlopen(const char *filename, int flag)
{
	if (lib.dlopen == NULL)
		get_real_dlsym();

	void *ret = lib.dlopen(filename, flag);

	if ((ret != NULL) && (filename != NULL)) {
		if ((!fnmatch("*libasound.so*", filename, 0)) | (!fnmatch("*libasound_module_*.so*", filename, 0)))
			alsa_unhook_so(filename); /* no audio stream duplication, thanks */
	}

	return ret;
}

__PUBLIC void *dlsym(void *handle, const char *symbol)
{
	return __main_dlsym(handle, symbol);
}

void *__main_dlsym(void *handle, const char *symbol)
{
	if (lib.dlsym == NULL)
		get_real_dlsym();

	void *ret = wrapped_func(symbol);
	if (ret)
		return ret;

	return lib.dlsym(handle, symbol);
}

__PUBLIC void *dlvsym(void *handle, const char *symbol, const char *version)
{
	return __main_dlvsym(handle, symbol, version);
}

void *__main_dlvsym(void *handle, const char *symbol, const char *version)
{
	if (lib.dlvsym == NULL)
		get_real_dlsym();

	void *ret = wrapped_func(symbol); /* should we too check for version? */
	if (ret)
		return ret;

	return lib.dlvsym(handle, symbol, version);
}

__PUBLIC void *__libc_dlsym(void *handle, const char *symbol)
{
	return __main___libc_dlsym(handle, symbol);
}

void *__main___libc_dlsym(void *handle, const char *symbol)
{
	if (lib.__libc_dlsym == NULL)
		get_real___libc_dlsym();

	void *ret = wrapped_func(symbol);
	if (ret)
		return ret;

	return lib.__libc_dlsym(handle, symbol);
}

/**  \} */
/**  \} */
