import socket
from dtls import (
    create_dtls_context,
    create_dtls_socket,
    create_ssl_handle,
    dtls_handshake,
    dtls_connect,
    dtls_send,
    bio_new_dgram,
    bio_set_mtu,
    ssl_set_bio
)

# 1. Créer le contexte DTLS
print("Création du contexte DTLS...")
ctx = create_dtls_context()
print(f"Contexte DTLS créé : {hex(ctx)}")

ssl = create_ssl_handle(ctx)

print(f"Handle ssl créé: {hex(ssl)}")

sockfd = create_dtls_socket()

print(f"Socket dtls créé: {hex(sockfd)}")

bio = bio_new_dgram(ssl, sockfd)
ssl_set_bio(ssl, bio)
bio_set_mtu(bio, 1400)

print(f"Socket attachée.")

dtls_connect(ctx, sockfd, "127.0.0.1", 7777)

print("Connexion O.K.")


# 4. Lancer le handshake DTLS
print("Lancement du handshake DTLS...")
try:
    dtls_handshake(ssl, is_server=False)  # Client DTLS
    print("Handshake DTLS réussi !")
    dtls_send(ssl, b"Hello from test dtls python!")
except OSError as e:
    print(f"Erreur lors du handshake : {e}")
