#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"  // Change cette IP si nécessaire
#define SERVER_PORT 7777
#define BUFFER_SIZE 1024

void handle_openssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void info_callback(const SSL *ssl, int where, int ret) {
    if (where & SSL_CB_LOOP) {
        printf("SSL state (%s): %s\n", SSL_get_version(ssl), SSL_state_string_long(ssl));
    }
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

    // 3. Activer la vérification des logs OpenSSL
    SSL_CTX_set_info_callback(ctx, info_callback);

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

    // 6. Connecter la socket UDP au serveur
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur: impossible de se connecter au serveur");
        exit(EXIT_FAILURE);
    }

    // 7. Créer une session DTLS
    ssl = SSL_new(ctx);
    if (!ssl) {
        handle_openssl_error("Erreur: impossible de créer une session SSL");
    }

    // 8. Attacher la socket UDP à OpenSSL via un BIO
    BIO *bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr);
    SSL_set_bio(ssl, bio, bio);

    printf("Tentative de handshake DTLS...\n");

    // 9. Effectuer le handshake DTLS
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        fprintf(stderr, "SSL_connect failed: %d\n", err);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
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
