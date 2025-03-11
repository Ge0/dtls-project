from dtls import create_dtls_context, create_dtls_socket, attach_socket_to_ssl, dtls_handshake

# 1. Créer le contexte DTLS
print("Création du contexte DTLS...")
ctx = create_dtls_context()
print(f"Contexte DTLS créé : {hex(ctx)}")

# 2. Créer un socket UDP
print("Création du socket UDP...")
sockfd = create_dtls_socket()
print(f"Socket UDP créé : {sockfd}")

# 3. Attacher le socket au contexte DTLS avec l'adresse cible (127.0.0.1:4433)
print("Attachement du socket au contexte DTLS...")
attach_socket_to_ssl(ctx, sockfd, "192.168.1.176", 7777)
print("Socket attaché avec succès !")

# 4. Lancer le handshake DTLS
print("Lancement du handshake DTLS...")
try:
    dtls_handshake(ctx, is_server=False)  # Client DTLS
    print("Handshake DTLS réussi !")
except OSError as e:
    print(f"Erreur lors du handshake : {e}")
