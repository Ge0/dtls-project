#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "172.19.112.1"
#define SERVER_PORT 7777
#define CERT_FILE "cert.pem"
#define KEY_FILE "key.pem"
#define BUFFER_SIZE 1024

void handle_openssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // 1. Initialiser OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // 2. Créer un contexte DTLS
    ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        handle_openssl_error("Erreur: impossible de créer le contexte SSL");
    }

    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    SSL_CTX_set_info_callback(ctx, (void (*)(const SSL *, int, int)) SSL_trace);



    // 4. Créer un socket UDP
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Erreur: impossible de créer le socket");
        exit(EXIT_FAILURE);
    }

    // 5. Configurer l'adresse du serveur
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Erreur: adresse serveur invalide");
        exit(EXIT_FAILURE);
    }

    // 6. Créer une session DTLS
    ssl = SSL_new(ctx);
    if (!ssl) {
        handle_openssl_error("Erreur: impossible de créer une session SSL");
    }

    // 7. Associer le socket au contexte DTLS
    BIO* bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
    if (!bio) {
        fprintf(stderr, "[ERROR] BIO_new_dgram() a échoué !\n");
        exit(EXIT_FAILURE);
    }
    printf("[DEBUG] BIO créé avec succès !\n");

    SSL_set_bio(ssl, bio, bio);

    long mtu = 1200;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_MTU, mtu, NULL);
    printf("[DEBUG] BIO attaché, MTU fixé à %ld\n", mtu);


    // 8. Connecter le socket au serveur
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur: impossible de se connecter au serveur");
        exit(EXIT_FAILURE);
    }

    // 9. Effectuer le handshake DTLS
    printf("[DEBUG] Tentative de handshake DTLS...\n");
    int ret = SSL_connect(ssl);
    printf("[DEBUG] SSL_connect return: %d\n", ret);
    if (ret <= 0) {
        handle_openssl_error("Erreur: échec du handshake DTLS");
        //ERR_print_errors_fp(stderr);
    }
    printf("Connexion DTLS établie avec le serveur !\n");

    // 10. Envoyer un message au serveur
    const char *msg = "Hello DTLS Server!";
    if (SSL_write(ssl, msg, strlen(msg)) <= 0) {
        handle_openssl_error("Erreur: échec de l'envoi des données");
    }
    printf("Message envoyé au serveur: %s\n", msg);

    // 11. Recevoir une réponse du serveur
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Réponse du serveur: %s\n", buffer);
    } else {
        handle_openssl_error("Erreur: échec de la réception des données");
    }

    // 12. Fermer la connexion
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    printf("Client DTLS terminé.\n");
    return 0;
}
