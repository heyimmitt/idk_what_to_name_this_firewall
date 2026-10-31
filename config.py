# "127.0.0.1" = only browsers on THIS machine can use the proxy (safe default).
# "0.0.0.0"   = listen on every network interface, so other machines on the network
#               can use it too (needed when the browser runs on a different PC)
HOST = "127.0.0.1"

# if startup fails with "address already in use" or (on Windows) "forbidden by its
# access permissions", the port is taken or reserved -- pick another, e.g. 18080
PORT = 8080
