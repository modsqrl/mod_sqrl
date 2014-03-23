/*
Copyright 2013 modsqrl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef SQRL_ENCODINGS_H
#define SQRL_ENCODINGS_H

#include "apr_pools.h"

/*
 * Encode binary data to URL-safe base64.
 * http://tools.ietf.org/html/rfc4648
 * @param pool Memory pool to allocate the returned encoded string.
 * @param plain Binary data to encode. '\0' does not terminate the data.
 * @param plain_len Number of bytes in plain to encode.
 * @return Base64url encoded string. Terminated by '\0'.
 */
char *sqrl_base64_encode(apr_pool_t * pool, const unsigned char *plain,
                         size_t plain_len);

/*
 * Decode binary data from a URL-safe base64 string.
 * http://tools.ietf.org/html/rfc4648
 * @param pool Allocates the decoded data.
 * @param b64 Base64 string to decode. '\0' terminated.
 * @param plain_len Number of bytes decoded. May be NULL.
 * @return The decoded plain data. '\0' does not terminate the data.
 */
unsigned char *sqrl_base64_decode(apr_pool_t * pool, const char *b64,
                                  size_t * plain_len);

/*
 * Encode binary data to a hexadecimal string.
 * @param p Memory pool to allocate the returned encoded string.
 * @param bin Binary data to encode. '\0' does not terminate the data.
 * @param binlen Number of bytes in bin to encode.
 * @param hexlen Stores the length of the returned hex string if it is not a
 *               NULL pointer.
 * @return Hexidecimal string. Terminated by '\0'.
 */
char *bin2hex(apr_pool_t * p, const unsigned char *bin,
              const size_t binlen, size_t * hexlen);

/*
 * Convert 4 bytes to a 32-bit integer.
 * @param bytes An array of, at least, 4 bytes.
 * @return A 32-bit integer.
 */
apr_int32_t bytes_to_int32(const unsigned char bytes[4]);

/*
 * Convert a 32-bit integer to 4 bytes.
 * @param bytes An array of, at least, 4 bytes to store the integer.
 * @param integer The integer to be broken up into 4 bytes.
 */
void int32_to_bytes(unsigned char bytes[4], apr_int32_t integer);


#endif
