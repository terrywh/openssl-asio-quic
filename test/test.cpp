#include "../quic/detail/ssl.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    SSL_CTX* ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    SSL* ssl = SSL_new(ctx);
    std::cout << "----------------------------\n";

    std::cout << "----------------------------\n";
    SSL_free(ssl);
    return 0;
}