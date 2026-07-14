#ifndef Py_SSL_H
#define Py_SSL_H

// Vendored from cpython/Modules/_ssl.c
typedef struct {
    PyObject_HEAD
    SSL_CTX *ctx;
    // ...
} PySSLContext;

#endif /* Py_SSL_H */
