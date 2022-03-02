#include <Python.h>

/* Include OpenSSL header files */
#include <openssl/ssl.h>

#include "_ssl.h"

static int always_pass_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    return 1;
}

PyDoc_STRVAR(set_verify_always_pass_doc, "Set's certificate validation to always pass");
static PyObject* set_verify_always_pass(PyObject *self, PyObject *args) {
    PyObject *mod_ssl;
    PyTypeObject *type_sslcontext;
    PySSLContext *context;
    int *always_pass;

    mod_ssl = PyImport_ImportModule("ssl");
    type_sslcontext = (PyTypeObject*) PyObject_GetAttrString(mod_ssl, "SSLContext") ;

    if (!PyArg_ParseTuple(args, "O!p", type_sslcontext, &context ,&always_pass)) {
        return NULL;
    }

    int verify_mode = SSL_CTX_get_verify_mode(context->ctx);
    if (always_pass) {
        SSL_CTX_set_verify(context->ctx, verify_mode, always_pass_callback);
    }
    else {
        SSL_CTX_set_verify(context->ctx, verify_mode, NULL);
    }

    Py_DECREF(mod_ssl);
    Py_RETURN_NONE;

}

static PyMethodDef ssl_workaround_methods[] = {
    {
        "set_verify_always_pass", set_verify_always_pass, METH_VARARGS,
        set_verify_always_pass_doc
    },
    {NULL, NULL, 0, NULL}
};

PyDoc_STRVAR(ssl_workaround_doc, "A workaround for accepting untrusted tls connections while still requesting a certificate");
static struct PyModuleDef ssl_workaround_definition = {
    PyModuleDef_HEAD_INIT,
    "pykdeconnect.ssl_workaround",
    ssl_workaround_doc,
    -1,
    ssl_workaround_methods
};

PyMODINIT_FUNC PyInit_ssl_workaround(void) {
    Py_Initialize();
    return PyModule_Create(&ssl_workaround_definition);
}
