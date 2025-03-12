from dtls import (
    create_dtls_context,
    attach_socket_to_ssl,
    create_dtls_socket,
    dtls_bind,
    dtls_accept,
    dtls_send,
    dtls_load_certificate_pem_file,
    dtls_load_private_private_key_pem_file,
    create_ssl_handle
)


ctx = create_dtls_context()
dtls_load_certificate_pem_file(ctx, "cert.pem")
dtls_load_private_private_key_pem_file(ctx, "key.pem")

ssl = create_ssl_handle(ctx)

socket = create_dtls_socket()
attach_socket_to_ssl(ssl, socket)

socket = dtls_bind(socket, 7777, ip="0.0.0.0")
print("Bind O.K.")
result = dtls_accept(ssl)
print(f"result = {result}")
dtls_send(ssl, b"Thank you for your business!")