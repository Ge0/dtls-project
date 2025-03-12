import socket
from dtls import (
    create_dtls_context,
    create_dtls_socket,
    attach_socket_to_ssl,
    create_ssl_handle,
    dtls_handshake,
    dtls_connect,
    dtls_send
)

# 1. Créer le contexte DTLS
print("Création du contexte DTLS...")
ctx = create_dtls_context()
print(f"Contexte DTLS créé : {hex(ctx)}")

ssl = create_ssl_handle(ctx)

print(f"Handle ssl créé: {hex(ssl)}")

sockfd = create_dtls_socket()

print(f"Socket dtls créé: {hex(sockfd)}")

attach_socket_to_ssl(ssl, sockfd)

print(f"Socket attachée.")

dtls_connect(ctx, sockfd, "172.19.112.1", 7777)

print("Connexion O.K.")


# 4. Lancer le handshake DTLS
print("Lancement du handshake DTLS...")
try:
    dtls_handshake(ssl, is_server=False)  # Client DTLS
    print("Handshake DTLS réussi !")
    dtls_send(ssl, b"Hello from test dtls python!")
except OSError as e:
    print(f"Erreur lors du handshake : {e}")
