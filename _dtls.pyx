# distutils: language = c
# distutils: sources = []

cimport cython
from libc.stdint cimport uintptr_t
from libc.string cimport memset
from posix.unistd cimport close
from cpython.bytes cimport PyBytes_FromStringAndSize
from libc.stdlib cimport malloc, free



cdef extern from "openssl/err.h":
    int ERR_get_error()
    char *ERR_error_string(int e, char *buf)

cdef extern from "netinet/in.h":
    ctypedef unsigned short sa_family_t
    unsigned short htons(unsigned short hostshort)
    cdef struct in_addr:
        unsigned long s_addr

    cdef struct sockaddr_in:
        sa_family_t sin_family
        unsigned short sin_port
        in_addr sin_addr


cdef extern from "sys/socket.h":
    cdef struct sockaddr:
        sa_family_t sa_family
        char sa_data[14]


    int socket(int domain, int type_, int protocol)
    int connect(int sockfd, const sockaddr *addr, int addrlen)
    int bind(int sockfd, const sockaddr* addr, int addrlen)
    int SOCK_DGRAM
    int SOCK_STREAM
    int AF_INET

cdef extern from "openssl/bio.h":
    ctypedef struct BIO
    BIO *BIO_new_dgram(int fd, int close_flag)
    int BIO_ctrl(BIO *bp, int cmd, long larg, void *parg)

cdef extern from "arpa/inet.h":
    unsigned long inet_addr(const char *cp)

cdef extern from "openssl/ssl.h":
    ctypedef struct SSL
    ctypedef struct SSL_CTX
    ctypedef struct EVP_PKEY
    int SSL_OP_NO_TICKET
    int BIO_CTRL_DGRAM_CONNECT

    SSL_CTX *SSL_CTX_new(void* method)
    void *DTLS_method()
    int *SSL_new(SSL_CTX *ctx)
    int SSL_read(SSL *ssl, char *buf, int num)
    int SSL_write(SSL *ssl, char *buf, int num)
    void SSL_free(SSL *ssl)
    void SSL_CTX_free(SSL_CTX *ctx)
    void SSL_set_bio(SSL* ssl, BIO *rbio, BIO *wbio)
    int SSL_connect(SSL* ssl)
    int SSL_accept(SSL *ssl)
    int SSL_set_options(SSL *ssl, long options)
    int SSL_set_cipher_list(SSL *ssl, const char *str)

    int SSL_write(SSL* ssl, const char* buf, int num)
    int SSL_read(SSL* ssl, char* buf, int num)

    int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
    int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
    int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d)
    int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx, const unsigned char *d, int len)
    int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
    int SSL_CTX_check_private_key(SSL_CTX *ctx)
    int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)

    int SSL_FILETYPE_PEM
    int SSL_FILETYPE_ASN1


def get_dtls_method():
    return <uintptr_t>DTLS_method()


def create_dtls_context():
    cdef SSL_CTX *ctx = SSL_CTX_new(DTLS_method())
    if ctx == NULL:
        raise MemoryError("Cannot create the DTLS context.")
    return <uintptr_t>ctx


def create_ssl_handle(uintptr_t ssl_context):
    cdef SSL *ssl = <SSL *>SSL_new(<SSL_CTX *>ssl_context)
    if ssl == NULL:
        raise MemoryError("Cannot create the SSL object.")
    return <uintptr_t>ssl


def create_dtls_socket():
    cdef int sockfd = socket(AF_INET, SOCK_DGRAM, 0)
    if sockfd < 0:
        raise OSError("Cannot create a UDP socket.")
    return sockfd


def dtls_bind(int sockfd, int port, str ip="127.0.0.1"):
    cdef sockaddr_in server_addr
    memset(&server_addr, 0, sizeof(server_addr))
    server_addr.sin_family = AF_INET
    server_addr.sin_port = htons(port)
    server_addr.sin_addr.s_addr = inet_addr(ip.encode())

    if bind(sockfd, <const sockaddr *>&server_addr, sizeof(server_addr)) < 0:
        raise OSError("Cannot bind the socket to the specified port.")
    return sockfd


def dtls_connect(uintptr_t ssl_ptr, int sockfd, str ip, int port):
    cdef SSL *ssl = <SSL *>ssl_ptr
    cdef BIO *bio = BIO_new_dgram(sockfd, 1)
    if bio == NULL:
        raise MemoryError("Cannot create a BIO DTLS.")
    
    SSL_set_bio(ssl, bio, bio)

    SSL_set_options(ssl, SSL_OP_NO_TICKET)
    cdef sockaddr_in server_addr
    memset(&server_addr, 0, sizeof(server_addr))
    server_addr.sin_family = AF_INET
    server_addr.sin_port = htons(port)
    server_addr.sin_addr.s_addr = inet_addr(ip.encode())

    if connect(sockfd, <const sockaddr *>&server_addr, sizeof(server_addr)) < 0:
        raise OSError("Cannot connect to the UDP socket.")

    BIO_ctrl(bio, BIO_CTRL_DGRAM_CONNECT, 0, &server_addr)


def attach_socket_to_ssl(uintptr_t ssl_ptr, int sockfd):
    cdef SSL *ssl = <SSL *>ssl_ptr
    cdef BIO *bio = BIO_new_dgram(sockfd, 1)
    if bio == NULL:
        raise MemoryError("Cannot create a BIO DTLS.")
    
    SSL_set_bio(ssl, bio, bio)


def dtls_accept(uintptr_t ssl_ptr):
    cdef SSL *ssl = <SSL *>ssl_ptr
    cdef int result
    cdef int err_code
    cdef char err_buf[256]
    result = SSL_accept(ssl)
    if result != 1:
        err_code = ERR_get_error()
        ERR_error_string(err_code, err_buf)
        raise OSError(f"SSL_accept failed: {err_buf.decode('utf-8')}")
    return result


def dtls_handshake(uintptr_t ssl_ptr, bint is_server=False):
    cdef SSL *ssl = <SSL *>ssl_ptr
    cdef int result

    if is_server:
        print("[DEBUG] Mode serveur")
        result = SSL_accept(ssl)
    else:
        print("[DEBUG] Mode client")
        result = SSL_connect(ssl)
    
    if result != 1:
        print("[DEBUG] Erreur dans SSL_connect/SSL_accept")
        raise OSError("DTLS handshake failed.")
    print("[DEBUG] Handshake réussi !")


def dtls_send(uintptr_t ssl_ptr, bytes data):
    cdef SSL *ssl = <SSL *>ssl_ptr
    cdef int sent_bytes = SSL_write(ssl, data, len(data))
    if sent_bytes <= 0:
        raise OSError("Failed to send DTLS data.")
    return sent_bytes


def dtls_recv(uintptr_t ssl_ptr, int bufsize):
    cdef SSL *ssl = <SSL *>ssl_ptr
    cdef char *buf = <char *>malloc(bufsize)
    if buf == NULL:
        raise MemoryError("malloc() failed.")

    cdef int received_bytes = SSL_read(ssl, buf, bufsize)

    if received_bytes <= 0:
        free(buf)
        raise OSError("DTLS reception failed or connection closed.")

    result = PyBytes_FromStringAndSize(buf, received_bytes)
    free(buf)
    return result


def dtls_load_certificate_pem_file(uintptr_t ctx_ptr, str filename):
    cdef SSL_CTX *ctx = <SSL_CTX *>ctx_ptr
    if SSL_CTX_use_certificate_file(ctx, filename.encode(), SSL_FILETYPE_PEM) != 1:
        raise OSError("Cannot load certificate.")


def dtls_load_private_private_key_pem_file(uintptr_t ctx_ptr, str filename):
    cdef SSL_CTX *ctx = <SSL_CTX *>ctx_ptr
    if SSL_CTX_use_PrivateKey_file(ctx, filename.encode(), SSL_FILETYPE_PEM) != 1:
        raise OSError("Cannot load private key.")