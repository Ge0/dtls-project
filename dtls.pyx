# distutils: language = c
# distutils: sources = []

cimport cython
from libc.stdint cimport uintptr_t
from libc.string cimport memset
from posix.unistd cimport close


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


def get_dtls_method():
    return <uintptr_t>DTLS_method()


def create_dtls_context():
    cdef SSL_CTX *ctx = SSL_CTX_new(DTLS_method())
    if ctx == NULL:
        raise MemoryError("Cannot create the DTLS context.")

    cdef SSL *ssl = <SSL *>SSL_new(ctx)
    if ssl == NULL:
        SSL_CTX_free(ctx)
        raise MemoryError("Cannot create the SSL object.")
    return <uintptr_t>ssl


def create_dtls_socket():
    cdef int sockfd = socket(AF_INET, SOCK_DGRAM, 0)
    if sockfd < 0:
        raise OSError("Cannot create a UDP socket.")
    return sockfd

def attach_socket_to_ssl(uintptr_t ssl_ptr, int sockfd, str ip, int port):
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

def dtls_handshake(uintptr_t ssl_ptr, bint is_server=False):
    cdef SSL *ssl = <SSL *>ssl_ptr
    cdef int result

    if is_server:
        result = SSL_accept(ssl)
    else:
        result = SSL_connect(ssl)
    
    if result != 1:
        raise OSError("DTLS handshake failed.")