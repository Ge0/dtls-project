#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 7777
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
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE] = "Thank you for your business!";
    
    // 1. Initialiser OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // 2. Créer le contexte DTLS
    ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) {
        handle_openssl_error("Erreur: impossible de créer le contexte SSL");
    }

    // 3. Charger le certificat et la clé privée
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error("Erreur: impossible de charger le certificat");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        handle_openssl_error("Erreur: impossible de charger la clé privée");
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        handle_openssl_error("Erreur: la clé privée ne correspond pas au certificat");
    }

    // 4. Créer un socket UDP
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Erreur: impossible de créer le socket");
        exit(EXIT_FAILURE);
    }

    // 5. Lier le socket à une adresse
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur: impossible de binder le socket");
        exit(EXIT_FAILURE);
    }

    // 6. Créer une session DTLS
    ssl = SSL_new(ctx);
    if (!ssl) {
        handle_openssl_error("Erreur: impossible de créer une session SSL");
    }

    // 7. Associer le socket au contexte DTLS
    BIO *bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    printf("En attente d'une connexion DTLS...\n");

    // 8. Recevoir une connexion DTLS (Handshake)
    if (SSL_accept(ssl) <= 0) {
        handle_openssl_error("Erreur: échec du handshake DTLS");
    }

    printf("Connexion DTLS acceptée !\n");

    // 9. Envoyer un message au client
    if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
        handle_openssl_error("Erreur: échec de l'envoi des données");
    }

    printf("Message envoyé au client.\n");

    // 10. Fermer la connexion
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    printf("Serveur DTLS fermé.\n");

    return 0;
}
