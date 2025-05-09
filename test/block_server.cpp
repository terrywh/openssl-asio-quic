#include "../quic.hpp"

int main(int argc, char* argv[]) {
    boost::asio::io_context io;

    boost::asio::ssl::context sslctx {SSL_CTX_new(OSSL_QUIC_server_method())};
    sslctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    sslctx.set_default_verify_paths();

    quic::server server{io, sslctx};

    quic::endpoint addr { boost::asio::ip::make_address("127.0.0.1"), 8080 };
    server.bind(addr);

    return 0;
}
