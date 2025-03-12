import socket
from dtls import (
    create_dtls_context,
    create_dtls_socket,
    attach_socket_to_ssl,
    dtls_handshake,
    dtls_connect,
    dtls_send
)

# 1. Créer le contexte DTLS
print("Création du contexte DTLS...")
ctx = create_dtls_context()
print(f"Contexte DTLS créé : {hex(ctx)}")

sockfd = create_dtls_socket()

dtls_connect(ctx, sockfd, "127.0.0.1", 7777)


# 4. Lancer le handshake DTLS
print("Lancement du handshake DTLS...")
try:
    dtls_handshake(ctx, is_server=False)  # Client DTLS
    print("Handshake DTLS réussi !")
    dtls_send(ctx, b"Hello from test dtls python!")
except OSError as e:
    print(f"Erreur lors du handshake : {e}")
