/**
 * Copyright (C) 2008-2026 isoft Infrastructure Software Co., Ltd.
 * SPDX-License-Identifier: LGPL-2.1-only-with-exception
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the
 * GNU Lesser General Public License as published by the Free Software Foundation; version 2.1.
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License along with this library;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * or see <https://www.gnu.org/licenses/>.
 */
/*
 ************************************************************************************************************************
 **
 **  @file               : TcpIp_TlsTypes.h
 **  @author             : pengfei.zhu
 **  @date               :
 **  @vendor             : isoft
 **  @description        : Tls data type definition
 **
 ***********************************************************************************************************************/

/*******************************************************************************
**                      REVISION   HISTORY                                    **
*******************************************************************************/
/* <VERSION>    <DATE>       <AUTHOR>        <REVISION LOG>
 *  V2.0.0    [20200828]  [pengfei.zhu]   Add Tcp_Tls function.
 *  V2.0.1    [20200928]  [pengfei.zhu]   QAC test.
 *  V2.2.0    [20250612]  [xiankun.zhou]  Code refactoring
 ******************************************************************************/

/*******************************************************************************
**                      Include Section                                       **
*******************************************************************************/

#ifndef TCPIP_TLSTYPES_H_
#define TCPIP_TLSTYPES_H_
#include "TcpIp_Cfg.h"

#if (TCPIP_TCP_TLS_ENABLED == STD_ON)
#include "Std_Types.h"

/* calculate const str length in compile */
#define CONST_STRLEN(s) ((uint32)(sizeof(s) - 1u))

#define TLS_USE_CSM_API STD_OFF

#define TLS_FLAGS_HANDSHAKE_DONE  (uint8)0x01u
#define TLS_FLAGS_UPPER_CALLED    (uint8)0x02u
#define TLS_FLAGS_RX_CLOSE_QUEUED (uint8)0x04u
#define TLS_FLAGS_RX_CLOSED       (uint8)0x08u
#define TLS_FLAGS_APPLDATA_SENT   (uint8)0x10u

/*************************************** Extensions *************************************************/
#define TLS_EXT_SERVERNAME             0u
#define TLS_EXT_SERVERNAME_HOSTNAME    0u
#define TLS_EXT_SUPPORTED_GROUPS       10u
#define TLS_EXT_SIGNATURE_ALG          13u
#define TLS_EXT_ENCRYPT_THEN_MAC       22u
#define TLS_EXT_EXTENDED_MASTER_SECRET 23u
#define TLS_EXT_RECORD_SIZE_LIMIT      28u
#define TLS_EXT_SUPPORTED_VERSIONS     43u
#define TLS_EXT_KEY_SHARE              51u
#define TLS_EXT_RENEGOTIATION_INFO     0xFF01u

#define TLS_SIG_ALG_RSA_PSS_SHA256   0x0804u
#define TLS_SIG_ALG_RSA_PKCS1_SHA256 0x0401u

#define TLS_COMPRESS_NULL 0u

/*************************** MESSAGE LENGTH DEFINITION **************************************/
#define TLS_HANDSHAKE_HEADER_LENGTH         4u
#define TLS_WRITE_CERTIFICATE_HEADER_LENGTH 7u

#define TLS_RECORD_HEADER_LENGTH 5u
#define TLS_TAG_LENGTH           16u
#define TLS_RECORD_SIZE_LIMIT    1024u
#define TLS_MAC_ADD              64u
#define TLS_IN_CONTENT_LEN       TLS_RECORD_SIZE_LIMIT
#define TLS_OUT_CONTENT_LEN      TLS_RECORD_SIZE_LIMIT

#define TLS_PAYLOAD_OVERHEAD (TLS_MAX_IV_LENGTH + TLS_MAC_ADD)
#define TLS_OUT_PAYLOAD_LEN  (TLS_PAYLOAD_OVERHEAD + TLS_OUT_CONTENT_LEN)
#define TLS_IN_PAYLOAD_LEN   (TLS_PAYLOAD_OVERHEAD + TLS_IN_CONTENT_LEN)
#define TLS_IN_BUFFER_LEN    (TLS_RECORD_HEADER_LENGTH + TLS_IN_PAYLOAD_LEN)
#define TLS_OUT_BUFFER_LEN   (TLS_RECORD_HEADER_LENGTH + TLS_OUT_PAYLOAD_LEN)

#define TLS_SIGN_MAX_LEN   256u
#define TLS_X25519_KEY_LEN 32u

/** Maximum length of any IV, in Bytes. */
#define TLS_MAX_IV_LENGTH    16u
/** Maximum block size of any cipher, in Bytes. */
#define TLS_MAX_BLOCK_LENGTH 16u

#define TLS_CERT_MAX_LENGTH   1024u
#define HS_MSG_MAX_LEN        2048u
#define TLS_RANDOM_LENGTH     ((uint32)32u)
#define TLS13_MAX_HASH_LENGTH 48u
#define TLS_RECORD_IV_MAX_LEN 32u
#define TLS_MASTER_SECRET_LEN 48u
#define TLS_WRITE_IV_MAX_LEN  12u
#define TLS_WRITE_KEY_MAX_LEN 32u
#define TLS_SESSION_ID_LEN    32u
#define TLS_DH_KEY_MAX_LEN    64u
#define TLS_HASH_MAX_LEN      64u
#define X25519_BASE_POINT_LEN 32u
#define TLS_ADD_DATA_LEN      5u
#define TLS_NONCE_LEN         12u
#define TLS12_VERIFY_DATA_LEN 12u

#define READ_WRITE_BLOCK_LEN  256u
#define IN_OUT_DATA_BLOCK_LEN (READ_WRITE_BLOCK_LEN + 96) /* reserve 96B for IV MAC and padding */

/********************************** cipher value ***************************************/
#define X25519_BASE_POINT 9u

/************************************** NET ERROR ******************************************/
/**< Return ok */
#define TLS_RETURN_OK                0x0000
/**< Failed to open a socket. */
#define TLS_ERR_NET_SOCKET_FAILED    (-0x0042)
/**< The connection to the given server / port failed. */
#define TLS_ERR_NET_CONNECT_FAILED   (-0x0044)
/**< Binding of the socket failed. */
#define TLS_ERR_NET_BIND_FAILED      (-0x0046)
/**< Could not listen on the socket. */
#define TLS_ERR_NET_LISTEN_FAILED    (-0x0048)
/**< Could not accept the incoming connection. */
#define TLS_ERR_NET_ACCEPT_FAILED    (-0x004A)
/**< Reading information from the socket failed. */
#define TLS_ERR_NET_RECV_FAILED      (-0x004C)
/**< Sending information through the socket failed. */
#define TLS_ERR_NET_SEND_FAILED      (-0x004E)
/**< Connection was reset by peer. */
#define TLS_ERR_NET_CONN_RESET       (-0x0050)
/**< Failed to get an IP address for the given hostname. */
#define TLS_ERR_NET_UNKNOWN_HOST     (-0x0052)
/**< Buffer is too small to hold the data. */
#define TLS_ERR_NET_BUFFER_TOO_SMALL (-0x0043)
/**< The context is invalid, eg because it was free()ed. */
#define TLS_ERR_NET_INVALID_CONTEXT  (-0x0045)
/**< Polling the net context failed. */
#define TLS_ERR_NET_POLL_FAILED      (-0x0047)
/**< Input invalid. */
#define TLS_ERR_NET_BAD_INPUT_DATA   (-0x0049)
/**< Read error */
#define TLS_ERR_SSL_WANT_READ        (-0x0051)
/**< Write error */
#define TLS_ERR_SSL_WANT_WRITE       (-0x0052)

/*********************************** CERT ERROR DEFINITION *******************************************/
/**< The certificate validity has expired. */
#define TLS_X509_BADCERT_EXPIRED       (-0x01)
/**< The certificate has been revoked (is on a CRL). */
#define TLS_X509_BADCERT_REVOKED       (-0x02)
/**< The certificate Common Name (CN) does not match with the expected CN. */
#define TLS_X509_BADCERT_CN_MISMATCH   (-0x04)
/**< The certificate is not correctly signed by the trusted CA. */
#define TLS_X509_BADCERT_NOT_TRUSTED   (-0x08)
/**< The CRL is not correctly signed by the trusted CA. */
#define TLS_X509_BADCRL_NOT_TRUSTED    (-0x10)
/**< The CRL is expired. */
#define TLS_X509_BADCRL_EXPIRED        (-0x20)
/**< Certificate was missing. */
#define TLS_X509_BADCERT_MISSING       (-0x40)
/**< Certificate verification was skipped. */
#define TLS_X509_BADCERT_SKIP_VERIFY   (-0x80)
/**< Other reason (can be used by verify callback) */
#define TLS_X509_BADCERT_OTHER         (-0x0100)
/**< The certificate validity starts in the future. */
#define TLS_X509_BADCERT_FUTURE        (-0x0200)
/**< The CRL is from the future */
#define TLS_X509_BADCRL_FUTURE         (-0x0400)
/**< Usage does not match the keyUsage extension. */
#define TLS_X509_BADCERT_KEY_USAGE     (-0x0800)
/**< Usage does not match the extendedKeyUsage extension. */
#define TLS_X509_BADCERT_EXT_KEY_USAGE (-0x1000)
/**< Usage does not match the nsCertType extension. */
#define TLS_X509_BADCERT_NS_CERT_TYPE  (-0x2000)
/**< The certificate is signed with an unacceptable hash. */
#define TLS_X509_BADCERT_BAD_MD        (-0x4000)
/**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define TLS_X509_BADCERT_BAD_PK        (-0x8000)
/**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
#define TLS_X509_BADCERT_BAD_KEY       (-0x010000)
/**< The CRL is signed with an unacceptable hash. */
#define TLS_X509_BADCRL_BAD_MD         (-0x020000)
/**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define TLS_X509_BADCRL_BAD_PK         (-0x040000)
/**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */
#define TLS_X509_BADCRL_BAD_KEY        (-0x080000)

/*********************************** general ERROR CODE *****************************************/
/**< The requested feature is not available. */
#define TLS_ERR_FEATURE_UNAVAILABLE           (-0x7080)
/**< Bad input parameters to function. */
#define TLS_ERR_BAD_INPUT_DATA                (-0x7100)
#define TLS_ERR_INVALID_MAC                   (-0x7180)
/**< Verification of the message MAC failed. */
#define TLS_ERR_INVALID_RECORD                (-0x7200)
/**< An invalid SSL record was received. */
#define TLS_ERR_CONN_EOF                      (-0x7280)
/**< The connection indicated an EOF. */
#define TLS_ERR_UNKNOWN_CIPHER                (-0x7300)
/**< An unknown cipher was received. */
/**< The server has no ciphersuites in common with the client. */
#define TLS_ERR_NO_CIPHER_CHOSEN              (-0x7380)
/**< No RNG was provided to the SSL module. */
#define TLS_ERR_NO_RNG                        (-0x7400)
/**< No client certification received from the client, but required by the authentication mode. */
#define TLS_ERR_NO_CLIENT_CERTIFICATE         (-0x7480)
/**< Our own certificate(s) is/are too large to send in an SSL message. */
#define TLS_ERR_CERTIFICATE_TOO_LARGE         (-0x7500)
/**< The own certificate is not set, but needed by the server. */
#define TLS_ERR_CERTIFICATE_REQUIRED          (-0x7580)
/**< The own private key or pre-shared key is not set, but needed. */
#define TLS_ERR_PRIVATE_KEY_REQUIRED          (-0x7600)
/**< No CA Chain is set, but required to operate. */
#define TLS_ERR_CA_CHAIN_REQUIRED             (-0x7680)
/**< An unexpected message was received from our peer. */
#define TLS_ERR_UNEXPECTED_MESSAGE            (-0x7700)
/**< A fatal alert message was received from our peer. */
#define TLS_ERR_FATAL_ALERT_MESSAGE           (-0x7780)
/**< Verification of our peer failed. */
#define TLS_ERR_PEER_VERIFY_FAILED            (-0x7800)
/**< The peer notified us that the connection is going to be closed. */
#define TLS_ERR_PEER_CLOSE_NOTIFY             (-0x7880)
/**< Processing of the ClientHello handshake message failed. */
#define TLS_ERR_BAD_HS_CLIENT_HELLO           (-0x7900)
/**< Processing of the ServerHello handshake message failed. */
#define TLS_ERR_BAD_HS_SERVER_HELLO           (-0x7980)
/**< Processing of the Certificate handshake message failed. */
#define TLS_ERR_BAD_HS_CERTIFICATE            (-0x7A00)
/**< Processing of the CertificateRequest handshake message failed. */
#define TLS_ERR_BAD_HS_CERTIFICATE_REQUEST    (-0x7A80)
/**< Processing of the ServerKeyExchange handshake message failed. */
#define TLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE    (-0x7B00)
/**< Processing of the ServerHelloDone handshake message failed. */
#define TLS_ERR_BAD_HS_SERVER_HELLO_DONE      (-0x7B80)
/**< Processing of the ClientKeyExchange handshake message failed. */
#define TLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE    (-0x7C00)
/**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public. */
#define TLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_RP (-0x7C80)
/**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret. */
#define TLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_CS (-0x7D00)
/**< Processing of the CertificateVerify handshake message failed. */
#define TLS_ERR_BAD_HS_CERTIFICATE_VERIFY     (-0x7D80)
/**< Processing of the ChangeCipherSpec handshake message failed. */
#define TLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC     (-0x7E00)
/**< Processing of the Finished handshake message failed. */
#define TLS_ERR_BAD_HS_FINISHED               (-0x7E80)
/**< Memory allocation failed */
#define TLS_ERR_ALLOC_FAILED                  (-0x7F00)
/**< Hardware acceleration function returned with error */
#define TLS_ERR_HW_ACCEL_FAILED               (-0x7F80)
/**< Hardware acceleration function skipped / left alone data */
#define TLS_ERR_HW_ACCEL_FALLTHROUGH          (-0x6F80)
/**< Processing of the compression / decompression failed */
#define TLS_ERR_COMPRESSION_FAILED            (-0x6F00)
/**< Handshake protocol not within min/max boundaries */
#define TLS_ERR_BAD_HS_PROTOCOL_VERSION       (-0x6E80)
/**< Processing of the NewSessionTicket handshake message failed. */
#define TLS_ERR_BAD_HS_NEW_SESSION_TICKET     (-0x6E00)
/**< Session ticket has expired. */
#define TLS_ERR_SESSION_TICKET_EXPIRED        (-0x6D80)
/**< Public key type mismatch (eg, asked for RSA key exchange and presented EC key) */
#define TLS_ERR_PK_TYPE_MISMATCH              (-0x6D00)
/**< Unknown identity received (eg, PSK identity) */
#define TLS_ERR_UNKNOWN_IDENTITY              (-0x6C80)
/**< Internal error (eg, unexpected failure in lower-level module) */
#define TLS_ERR_INTERNAL_ERROR                (-0x6C00)
/**< A counter would wrap (eg, too many messages exchanged). */
#define TLS_ERR_COUNTER_WRAPPING              (-0x6B80)
/**< Unexpected message at ServerHello in renegotiation. */
#define TLS_ERR_WAITING_SERVER_HELLO_RENEGO   (-0x6B00)
/**< DTLS client must retry for hello verification */
#define TLS_ERR_HELLO_VERIFY_REQUIRED         (-0x6A80)
/**< A buffer is too small to receive or write a message */
#define TLS_ERR_BUFFER_TOO_SMALL              (-0x6A00)
/**< None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages). */
#define TLS_ERR_NO_USABLE_CIPHERSUITE         (-0x6980)
/**< No data of requested type currently available on underlying transport. */
#define TLS_ERR_WANT_READ                     (-0x6900)
/**< Connection requires a write call. */
#define TLS_ERR_WANT_WRITE                    (-0x6880)
/**< The operation timed out. */
#define TLS_ERR_TIMEOUT                       (-0x6800)
/**< The client initiated a reconnect from the same port. */
#define TLS_ERR_CLIENT_RECONNECT              (-0x6780)
/**< Record header looks valid but is not expected. */
#define TLS_ERR_UNEXPECTED_RECORD             (-0x6700)
/**< The alert message received indicates a non-fatal error. */
#define TLS_ERR_NON_FATAL                     (-0x6680)
/**< Couldn't set the hash for verifying CertificateVerify */
#define TLS_ERR_INVALID_VERIFY_HASH           (-0x6600)
/**< Internal-only message signaling that further message-processing should be done */
#define TLS_ERR_CONTINUE_PROCESSING           (-0x6580)
/**< The asynchronous operation is not completed yet. */
#define TLS_ERR_ASYNC_IN_PROGRESS             (-0x6500)
/**< Internal-only message signaling that a message arrived early. */
#define TLS_ERR_EARLY_MESSAGE                 (-0x6480)
/**< A cryptographic operation is in progress. Try again later. */
#define TLS_ERR_CRYPTO_IN_PROGRESS            (-0x7000)

/********************************** MESSAGE TYPE ******************************************/
#define TLS_MSG_TYPE_CHANGE_CIPHER_SPEC 20u
#define TLS_MSG_TYPE_ALERT              21u
#define TLS_MSG_TYPE_HANDSHAKE          22u
#define TLS_MSG_TYPE_APPLICATION_DATA   23u

/******************************** HANDSHAKE HEADER TYPE ***********************************/
#define TLS_HS_TYPE_HELLO_REQUEST        0u
#define TLS_HS_TYPE_CLIENT_HELLO         1u
#define TLS_HS_TYPE_SERVER_HELLO         2u
#define TLS_HS_TYPE_HELLO_VERIFY_REQUEST 3u
#define TLS_HS_TYPE_NEW_SESSION_TICKET   4u
#define TLS_HS_TYPE_ENCRYPTED_EXTENSIONS 8u
#define TLS_HS_TYPE_CERTIFICATE          11u
#define TLS_HS_TYPE_SERVER_KEY_EXCHANGE  12u
#define TLS_HS_TYPE_CERTIFICATE_REQUEST  13u
#define TLS_HS_TYPE_SERVER_HELLO_DONE    14u
#define TLS_HS_TYPE_CERTIFICATE_VERIFY   15u
#define TLS_HS_TYPE_CLIENT_KEY_EXCHANGE  16u
#define TLS_HS_TYPE_FINISHED             20u

/******************* TLS1.2 SUPPORT CIPHERSUITES (Official IANA names) *******************/
#define TLS_RESERVED 0x4a4au

#define TLS_RSA_WITH_AES_128_CBC_SHA    0x2Fu
#define TLS_RSA_WITH_NULL_SHA256        0x3Bu
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x3Cu
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x3Du

#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 0x67u
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 0x6Bu

#define TLS_RSA_WITH_AES_128_GCM_SHA256     0x9Cu
#define TLS_RSA_WITH_AES_256_GCM_SHA384     0x9Du
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 0x9Eu
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 0x9Fu

#define TLS_PSK_WITH_AES_128_GCM_SHA256     0xA8u
#define TLS_PSK_WITH_AES_256_GCM_SHA384     0xA9u
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 0xAAu
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 0xABu
#define TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 0xACu
#define TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 0xADu

#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     0xBAu
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 0xBEu

#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     0xC0u
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 0xC4u

#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC023u
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xC024u
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  0xC025u
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  0xC026u
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   0xC027u
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   0xC028u
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256    0xC029u
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384    0xC02Au

#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02Bu
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02Cu
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256  0xC02Du
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384  0xC02Eu
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02Fu
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xC030u
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256    0xC031u
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384    0xC032u

#define TLS_RSA_WITH_ARIA_128_CBC_SHA256         0xC03Cu
#define TLS_RSA_WITH_ARIA_256_CBC_SHA384         0xC03Du
#define TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256     0xC044u
#define TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384     0xC045u
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 0xC048u
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 0xC049u
#define TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256  0xC04Au
#define TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384  0xC04Bu
#define TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256   0xC04Cu
#define TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384   0xC04Du
#define TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256    0xC04Eu
#define TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384    0xC04Fu
#define TLS_RSA_WITH_ARIA_128_GCM_SHA256         0xC050u
#define TLS_RSA_WITH_ARIA_256_GCM_SHA384         0xC051u
#define TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256     0xC052u
#define TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384     0xC053u
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 0xC05Cu
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 0xC05Du
#define TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256  0xC05Eu
#define TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384  0xC05Fu
#define TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256   0xC060u
#define TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384   0xC061u
#define TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256    0xC062u
#define TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384    0xC063u
#define TLS_PSK_WITH_ARIA_128_CBC_SHA256         0xC064u
#define TLS_PSK_WITH_ARIA_256_CBC_SHA384         0xC065u
#define TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256     0xC066u
#define TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384     0xC067u
#define TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256     0xC068u
#define TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384     0xC069u
#define TLS_PSK_WITH_ARIA_128_GCM_SHA256         0xC06Au
#define TLS_PSK_WITH_ARIA_256_GCM_SHA384         0xC06Bu
#define TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256     0xC06Cu
#define TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384     0xC06Du
#define TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256     0xC06Eu
#define TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384     0xC06Fu
#define TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256   0xC070u
#define TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384   0xC071u

#define TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256         0xC07Au
#define TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384         0xC07Bu
#define TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     0xC07Cu
#define TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     0xC07Du
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 0xC086u
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 0xC087u
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  0xC088u
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  0xC089u
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256   0xC08Au
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384   0xC08Bu
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256    0xC08Cu
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384    0xC08Du

#define TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256     0xC08Eu
#define TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384     0xC08Fu
#define TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 0xC090u
#define TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 0xC091u
#define TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 0xC092u
#define TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 0xC093u

#define TLS_RSA_WITH_AES_128_CCM       0xC09Cu
#define TLS_RSA_WITH_AES_256_CCM       0xC09Du
#define TLS_DHE_RSA_WITH_AES_128_CCM   0xC09Eu
#define TLS_DHE_RSA_WITH_AES_256_CCM   0xC09Fu
#define TLS_RSA_WITH_AES_128_CCM_8     0xC0A0u
#define TLS_RSA_WITH_AES_256_CCM_8     0xC0A1u
#define TLS_DHE_RSA_WITH_AES_128_CCM_8 0xC0A2u
#define TLS_DHE_RSA_WITH_AES_256_CCM_8 0xC0A3u
#define TLS_PSK_WITH_AES_128_CCM       0xC0A4u
#define TLS_PSK_WITH_AES_256_CCM       0xC0A5u
#define TLS_DHE_PSK_WITH_AES_128_CCM   0xC0A6u
#define TLS_DHE_PSK_WITH_AES_256_CCM   0xC0A7u
#define TLS_PSK_WITH_AES_128_CCM_8     0xC0A8u
#define TLS_PSK_WITH_AES_256_CCM_8     0xC0A9u
#define TLS_DHE_PSK_WITH_AES_128_CCM_8 0xC0AAu
#define TLS_DHE_PSK_WITH_AES_256_CCM_8 0xC0ABu

#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM   0xC0ACu
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM   0xC0ADu
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 0xC0AEu
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 0xC0AFu

/* RFC 7905 */
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA8u
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA9u
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xCCAAu
#define TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         0xCCABu
#define TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   0xCCACu
#define TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     0xCCADu
#define TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     0xCCAEu

/************************ TLS 1.3 SUPPORT CIPHERSUITES *********************/
#define TLS_AES_128_GCM_SHA256       0x1301u
#define TLS_AES_256_GCM_SHA384       0x1302u
#define TLS_CHACHA20_POLY1305_SHA256 0x1303u
#define TLS_AES_128_CCM_SHA256       0x1304u
#define TLS_AES_128_CCM_8_SHA256     0x1305u

/* Supported Signature and Hash algorithms (For TLS 1.2) RFC 5246 section 7.4.1.4.1 */
#define TLS_SIG_ANON  0u
#define TLS_SIG_RSA   1u
#define TLS_SIG_ECDSA 3u

#define TLS_HASH_NONE   0u
#define TLS_HASH_MD5    1u
#define TLS_HASH_SHA1   2u
#define TLS_HASH_SHA224 3u
#define TLS_HASH_SHA256 4u
#define TLS_HASH_SHA384 5u
#define TLS_HASH_SHA512 6u

/************************ TLS 1.3 Signature Scheme List  *********************/
#define TLS_RSA_PKCS1_SHA256    0x0401u
#define TLS_RSA_PSS_RSAE_SHA256 0x0804u

/********************************** group id *****************************************/
#define ECDHE_GROUP_SECP256R1 0x17u
#define ECDHE_GROUP_SECP384R1 0x18u
#define ECDHE_GROUP_SECP521R1 0x19u
#define ECDHE_GROUP_X25519    0x1Du

/*********************************** ERROR CODE *****************************************/
#define TLS_ERR_INIT_VAL                  0x1000u
#define TLS_ERR_READ_ERR                  0x1001u
#define TLS_ERR_BAD_MESSAGE_ERR           0x1002u
#define TLS_ERR_DERIVE_KEY                0x1003u
#define TLS_ERR_FRAGMENT_ERR              0x1004u
#define TLS_ERR_ENCRYPT_THEN_MAC          0x1005u
#define TLS_ERR_ENCRYPT_ERROR             0x1006u
#define TLS_ERR_HS_TYPE_ERR               0x1007u
#define TLS_ERR_SEND_FAILED               0x1008u
#define TLS_ERR_MEM_OVERFLOW              0x1009u
#define TLS_ERR_CSM_HASH_ERROR            0x1010u
#define TLS_ERR_HS_INIT                   0x1011u
#define TLS_ERR_CERTIFICATE_VERIFY_FAILED 0x1012u

/********************************** TLS VERSION ***************************************/
#define TLS_MAJOR_VERSION_3   3u
#define TLS_MINOR_VERSION_0   0u
#define TLS_MINOR_VERSION_1   1u
#define TLS_MINOR_VERSION_2   2u
#define TLS_MINOR_VERSION_3   3u /*!< TLS v1.2 */
#define TLS_MINOR_VERSION_4   4u /*!< TLS v1.3 */
#define TLS_MIN_MAJOR_VERSION TLS_MAJOR_VERSION_3
#define TLS_MIN_MINOR_VERSION TLS_MINOR_VERSION_3

/********************************** TLS LABEL ***************************************/
#define TLS_LABEL_EMPTY                 ""
#define TLS_LABEL_IV                    "iv"
#define TLS_LABEL_KEY                   "key"
#define TLS_LABEL_TLS13                 "tls13 "
#define TLS_LABEL_DERIVED               "derived"
#define TLS_LABEL_FINISHED              "finished"
#define TLS_LABEL_MASTER_SECRET         "master secret"
#define TLS_LABEL_KEY_EXPANSION         "key expansion"
#define TLS_LABEL_TLS12_CLIENT_FINISHED "client finished"
#define TLS_LABEL_TLS12_SERVER_FINISHED "server finished"
#define TLS_LABEL_TLS13_SERVER_VERIFY   "TLS 1.3, server CertificateVerify"
#define TLS_LABEL_C_HS_TRAFFIC          "c hs traffic"
#define TLS_LABEL_S_HS_TRAFFIC          "s hs traffic"
#define TLS_LABEL_C_AP_TRAFFIC          "c ap traffic"
#define TLS_LABEL_S_AP_TRAFFIC          "s ap traffic"

typedef uint8 TcpIp_TlsKeyExchangeType;
#define TLS_KEY_EXCHANGE_RSA   ((TcpIp_TlsKeyExchangeType)(0u))
#define TLS_KEY_EXCHANGE_ECDHE ((TcpIp_TlsKeyExchangeType)(1u))

/* TLS state machine  */
typedef uint8 TcpIp_TlsHandshakeStatusType;
#define TLS_HELLO_REQUEST                    ((TcpIp_TlsHandshakeStatusType)(0u))
#define TLS_CLIENT_HELLO                     ((TcpIp_TlsHandshakeStatusType)(1u))
#define TLS_SERVER_HELLO                     ((TcpIp_TlsHandshakeStatusType)(2u))
#define TLS_SERVER_CERTIFICATE               ((TcpIp_TlsHandshakeStatusType)(3u))
#define TLS_SERVER_KEY_EXCHANGE              ((TcpIp_TlsHandshakeStatusType)(4u))
#define TLS_CERTIFICATE_REQUEST              ((TcpIp_TlsHandshakeStatusType)(5u))
#define TLS_SERVER_HELLO_DONE                ((TcpIp_TlsHandshakeStatusType)(6u))
#define TLS_CLIENT_CERTIFICATE               ((TcpIp_TlsHandshakeStatusType)(7u))
#define TLS_CLIENT_KEY_EXCHANGE              ((TcpIp_TlsHandshakeStatusType)(8u))
#define TLS_CERTIFICATE_VERIFY               ((TcpIp_TlsHandshakeStatusType)(9u))
#define TLS_CLIENT_CHANGE_CIPHER_SPEC        ((TcpIp_TlsHandshakeStatusType)(10u))
#define TLS_CLIENT_FINISHED                  ((TcpIp_TlsHandshakeStatusType)(11u))
#define TLS_SERVER_CHANGE_CIPHER_SPEC        ((TcpIp_TlsHandshakeStatusType)(12u))
#define TLS_ENCRYPTED_EXTENSIONS             ((TcpIp_TlsHandshakeStatusType)(13u))
#define TLS_SERVER_FINISHED                  ((TcpIp_TlsHandshakeStatusType)(14u))
#define TLS_FLUSH_BUFFERS                    ((TcpIp_TlsHandshakeStatusType)(15u))
#define TLS_HANDSHAKE_WRAPUP                 ((TcpIp_TlsHandshakeStatusType)(16u))
#define TLS_HANDSHAKE_DONE                   ((TcpIp_TlsHandshakeStatusType)(17u))
#define TLS_SERVER_NEW_SESSION_TICKET        ((TcpIp_TlsHandshakeStatusType)(18u))
#define TLS_SERVER_HELLO_VERIFY_REQUEST_SENT ((TcpIp_TlsHandshakeStatusType)(19u))

typedef struct
{
    boolean supportTls13;
#if (STD_ON == TLS_ENCRYPT_THEN_MAC)
    boolean encryptThenMac;
#endif
    TcpIp_TlsHandshakeStatusType state; /* handshake: state machine */
    TcpIp_TlsKeyExchangeType     KeyExchange;
    uint8                        minorVersion;
    uint8                        handshakeId;
    uint8                        ciphersuiteId;
    uint8                        masterSecretLen;
    uint8                        DHKeyLen;
    uint8                        sessionIdLen;
    uint8                        hashLen;
    uint8                        write_MAC_key_len;
    uint8                        write_key_len;
    uint8                        write_IV_len;
    uint8                        record_IV_length;
    uint8                        inRecordContentType;  /**< current in record type */
    uint8                        outRecordContentType; /**< current out record type */

    uint16 recordSizeLimit;        /**< rfc8449 */
    uint16 inRecordContentLength;  /**< current record content length */
    uint16 inRemainingLen;         /**< remaining length of fragment */
    uint16 outRecordContentLength; /**< current record content length */
    uint16 outRemainingLen;        /**< remaining length of unsent data */

    const TcpIp_TlsConnectionConfigType*            connectionConfigPtr;
    const TcpIp_TlsCiphersuiteDefinitionConfigType* ciphersuiteDefinitionPtr;
    const TcpIp_TlsCiphersuiteWorkerConfigType*     ciphersuiteWorkerPtr;
    const TcpIp_TlsCertificateIdentityConfigType*   certificateIdentityPtr;
    const TcpIp_TlsHandshakeConfigType*             handshakePtr;

    struct pbuf* inPBuf;                /**< TLS data stored in inBufStart->payload */
    uint8*       inBufPtr;              /**< current tls data pointer, following data reading */
    uint8*       inRecordHdrStart;      /**< current record header pointer */
    uint8*       inRecordContentStart;  /**< current record content start pointer */
    struct pbuf* outPBuf;               /**< TLS data stored in outBufStart->payload */
    uint32       outTotalLen;           /**< total length of TLS data */
    uint8*       outRecordHdrStart;     /**< current record header pointer */
    uint8*       outRecordContentStart; /**< current record content start pointer */

    uint64 seqNum;
    uint64 peerSeqNum;
    uint8  preMasterSecret[TLS_MASTER_SECRET_LEN];
    uint8  masterSecret[TLS_MASTER_SECRET_LEN];
    uint8  ECDHEKey[TLS_DH_KEY_MAX_LEN];
    uint8  sessionId[TLS_SESSION_ID_LEN];
    uint8  clientRandom[TLS_RANDOM_LENGTH];
    uint8  serverRandom[TLS_RANDOM_LENGTH];
    uint8  client_write_IV[TLS_WRITE_IV_MAX_LEN];
    uint8  server_write_IV[TLS_WRITE_IV_MAX_LEN];
    uint8  client_write_MAC_key[TLS_WRITE_KEY_MAX_LEN];
    uint8  server_write_MAC_key[TLS_WRITE_KEY_MAX_LEN];
    uint8  client_write_key[TLS_WRITE_KEY_MAX_LEN];
    uint8  server_write_key[TLS_WRITE_KEY_MAX_LEN];
    uint8  client_finished_key[TLS_WRITE_KEY_MAX_LEN]; /* only for tls 1.3 */
    uint8  server_finished_key[TLS_WRITE_KEY_MAX_LEN]; /* only for tls 1.3 */
    uint8  recordIV[TLS_RECORD_IV_MAX_LEN];
    uint8  handshakeMsgHash[TLS_HASH_MAX_LEN]; /**< for message hash of finished */

#if (TLS_USE_CSM_API != STD_ON)
    uint8  handshake_messages[HS_MSG_MAX_LEN];
    uint32 handshake_messagesLen;
#endif
} tlsContext;

typedef struct TcpIp_TlsSocketDataTag
{
    uint8                          flags;
    struct tcp_pcb*                PcbPtr;
    struct pbuf*                   rx; /* chain of rx pbufs (before decryption) */
    uint32                         rxPassedUnrecved;
    uint16                         bioBytesRead;
    struct TcpIp_TlsSocketDataTag* next;
    tlsContext                     socketTlsContext;
} TcpIp_TlsSocketDataType;

#if (TCPIP_TLS_HASH_TABLE_LOOKUP == STD_ON)
typedef struct TcpIp_TlsHashBucket
{
    uint32                               netSegment;  /* netSegment = ip&mask, use network segment to save time */
    const TcpIp_TlsConnectionConfigType* tlsCnCfgPtr; /* port stored in tlsCnCfgPtr */
    struct TcpIp_TlsHashBucket*          next;
} TcpIp_TlsHashBucket;
#endif

#endif /* TCPIP_TCP_TLS_ENABLED */
#endif /* TCPIP_TLSTYPES_H_ */
