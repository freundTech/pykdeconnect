#ifndef Py_SSL_H
#define Py_SSL_H

/*
 * ssl module state
 */
typedef struct {
    /* Types */
    PyTypeObject *PySSLContext_Type;
    PyTypeObject *PySSLSocket_Type;
    PyTypeObject *PySSLMemoryBIO_Type;
    PyTypeObject *PySSLSession_Type;
    PyTypeObject *PySSLCertificate_Type;
    /* SSL error object */
    PyObject *PySSLErrorObject;
    PyObject *PySSLCertVerificationErrorObject;
    PyObject *PySSLZeroReturnErrorObject;
    PyObject *PySSLWantReadErrorObject;
    PyObject *PySSLWantWriteErrorObject;
    PyObject *PySSLSyscallErrorObject;
    PyObject *PySSLEOFErrorObject;
    /* Error mappings */
    PyObject *err_codes_to_names;
    PyObject *err_names_to_codes;
    PyObject *lib_codes_to_names;
    /* socket type from module CAPI */
    PyTypeObject *Sock_Type;
} _sslmodulestate;

// Start copied from _ssl.c
typedef struct {
    PyObject_HEAD
    SSL_CTX *ctx;
    unsigned char *alpn_protocols;
    unsigned int alpn_protocols_len;
    PyObject *set_sni_cb;
    int check_hostname;
    /* OpenSSL has no API to get hostflags from X509_VERIFY_PARAM* struct.
     * We have to maintain our own copy. OpenSSL's hostflags default to 0.
     */
    unsigned int hostflags;
    int protocol;
#ifdef TLS1_3_VERSION
    int post_handshake_auth;
#endif
    PyObject *msg_cb;
    PyObject *keylog_filename;
    BIO *keylog_bio;
    /* Cached module state, also used in SSLSocket and SSLSession code. */
    _sslmodulestate *state;
} PySSLContext;
// End copied from _ssl.c


#endif /* Py_SSL_H */
