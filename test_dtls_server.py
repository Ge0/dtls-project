from dtls import (
    create_dtls_context,
    attach_socket_to_ssl,
    create_dtls_socket,
    dtls_bind,
    dtls_accept,
    dtls_send
)


ctx = create_dtls_context()

socket = create_dtls_socket()
attach_socket_to_ssl(ctx, socket)
socket = dtls_bind(socket, 7777, ip="0.0.0.0")
print("Bind O.K.")
result = dtls_accept(ctx)
print(f"result = {result}")
dtls_send(ctx, b"Thank you for your business!")