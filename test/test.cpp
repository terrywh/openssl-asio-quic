#include "../quic/detail/ssl.hpp"
#include <boost/asio/buffer.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    SSL_CTX* ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    SSL* ssl = SSL_new(ctx);
    std::cout << "----------------------------\n";

    std::string memory { "12345678901234567890" };
    memory.clear();
    boost::asio::dynamic_string_buffer buffer{memory};
    buffer.grow(1024);
    boost::asio::mutable_buffer m = buffer.data(0, 1024);

    memset(m.data(), 0, m.size());

    std::cout << "----------------------------\n";
    SSL_free(ssl);
    return 0;
}