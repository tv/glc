/**
 * \file glc/core/file.h
 * \brief file io
 * \author Pyry Haulos <pyry.haulos@gmail.com>
 * \date 2007-2008
 * For conditions of distribution and use, see copyright notice in glc.h
 */

/**
 * \addtogroup core
 *  \{
 * \defgroup file file io
 *  \{
 */

#ifndef _stream_H
#define _stream_H

#include <packetstream.h>
#include <glc/common/glc.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief file object
 */
typedef struct stream_s* stream_t;

/**
 * \brief initialize file object
 * Writing is done in its own thread.
 * \code
 * // writing example
 * stream_init(*file, glc);
 * stream_open_target(file, "/tmp/stream.glc");
 * ...
 * stream_write_info(file, &info, name, date);
 * stream_write_process_start(file, buffer);
 * ...
 * stream_write_process_wait(file);
 * stream_close_target(file);
 * stream_destroy(file);
 * \endcode
 *
 * Reading stream from file is done in same thread.
 * \code
 * // reading example
 * stream_init(*file, glc);
 * stream_open_source(file, "/tmp/stream.glc");
 * ...
 * stream_read_info(file, &info, &name, &date);
 * stream_read(file, buffer);
 * stream_close_source(file);
 * ...
 * stream_destroy(file);
 * free(name);
 * free(date);
 * \endcode
 *
 * stream_write_info() must be called before starting write
 * process.
 *
 * Like in writing, stream_read_info() must be called before
 * calling stream_read().
 *
 * One stream file can actually hold multiple individual
 * streams: [info0][stream0][info1][stream1]...
 * \param file file object
 * \param glc glc
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_init(stream_t *file, glc_t *glc);

/**
 * \brief set sync mode
 * \note this must be set before opening file
 * \param file file object
 * \param sync 0 = no forced synchronization, 1 = force writing immediately to device
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_set_sync(stream_t stream, int sync);

/**
 * \brief set callback function
 * Callback is called when callback_request message is encountered
 * in stream.
 * \param file file object
 * \param callback callback function address
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_set_callback(stream_t stream, callback_request_func_t callback);

/**
 * \brief open file for writing
 * \note this calls stream_set_target()
 * \param file file object
 * \param host target hostname
 * \param port target port
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_open_target(stream_t stream, const char *host, int port);

/**
 * \brief setup file descriptor for writing
 *
 * This locks file descriptor and truncates it. If file descriptor
 * can't be locked this will fail.
 * \param file file object
 * \param socketfd file descriptor
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_set_target(stream_t stream, int socketfd);

/**
 * \brief close target file descriptor
 * \param file file object
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_close_target(stream_t stream);

/**
 * \brief write stream information header to file
 * \param file file object
 * \param info info structure
 * \param info_name app name
 * \param info_date date
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_write_info(stream_t stream, glc_stream_info_t *info,
			     const char *info_name, const char *info_date);

/**
 * \brief write EOF message to file
 * \param file file object
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_write_eof(stream_t stream);

/**
 * \brief write current stream state to file
 * \param file file object
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_write_state(stream_t stream);

/**
 * \brief start writing process
 *
 * file will write all data from source buffer to target file
 * in a custom format that can be read back using stream_read()
 * \param file file object
 * \param from source buffer
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_write_process_start(stream_t stream, ps_buffer_t *from);

/**
 * \brief block until process has finished
 * \param file file object
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_write_process_wait(stream_t stream);

/**
 * \brief set source file descriptor
 * \param file file object
 * \param socketfd file descriptor
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_set_source(stream_t stream, int socketfd);

/**
 * \brief close source file
 * \param file file object
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_close_source(stream_t stream);

/**
 * \brief test if given stream version is supported
 * \param version version to test
 * \return 0 if is supported, otherwise ENOTSUP
 */
__PUBLIC int stream_test_stream_version(u_int32_t version);

/**
 * \brief destroy file object
 * \param file file object
 * \return 0 on success otherwise an error code
 */
__PUBLIC int stream_destroy(stream_t stream);

#ifdef __cplusplus
}
#endif

#endif

/**  \} */
/**  \} */
