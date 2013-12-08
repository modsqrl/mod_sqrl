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

#include "apr_pools.h"
#include "sqrl.h"


#ifndef SQRL_UTILS_H
#define SQRL_UTILS_H


/*
 * Get the clients IP address.
 * @param r Request.
 */
char *get_client_ip(request_rec * r);

/*
 * Encode binary data to URL-safe base64.
 * http://tools.ietf.org/html/rfc4648
 * @param p Memory pool to allocate the returned encoded string.
 * @param plain Binary data to encode. '\0' does not terminate the data.
 * @param plain_len Number of bytes in plain to encode.
 * @return Base64url encoded string. Terminated by '\0'.
 */
char *sqrl_base64url_encode(apr_pool_t * p, const unsigned char *plain,
                            unsigned int plain_len);

/*
 * Decode binary data from a URL-safe base64 string.
 * http://tools.ietf.org/html/rfc4648
 * @param p Allocates the decoded data.
 * @param encoded Base64 string to decode. '\0' terminated. Does not need
 *                padding.
 * @param plain_len Number of bytes decoded. May be NULL.
 * @return The decoded plain data. '\0' does not terminate the data.
 */
unsigned char *sqrl_base64url_decode(apr_pool_t * p, const char *encoded,
                                     int *plain_len);

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
              const apr_size_t binlen, apr_size_t * hexlen);

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

/*
 * Create a string representation of a sqrl_rec.
 * @param pool Allocate the new string.
 * @param sqrl sqrl_rec to stringify.
 * @return String of the sqrl_rec.
 */
const char *sqrl_to_string(apr_pool_t * pool, sqrl_rec * sqrl);

apr_status_t write_out(request_rec * r, const char *response);


#endif
