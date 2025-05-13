#include "../quic.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

static int select_alpn_cb(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *in,
                       unsigned int in_len, void *arg) {
    quic::application_protocol_list* alpn = static_cast<quic::application_protocol_list*>(arg);
    if (SSL_select_next_proto((unsigned char **)out, out_len, *alpn, alpn->size(), in, in_len) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

void run(quic::connection& conn) {
    quic::stream stream;
    std::cout << std::format("{:-^64}\n", "waiting for stream");
    conn.accept_stream(stream);
    std::cout << std::format("{:-^64}\n", "stream accepted");

    stream.shutdown(boost::asio::socket_base::shutdown_both);
}

int main(int argc, char* argv[]) {
    boost::asio::io_context io;
    quic::application_protocol_list alpn {"http/1.0"};
    boost::asio::ssl::context sslctx {SSL_CTX_new(OSSL_QUIC_server_method())};
    sslctx.use_certificate_chain_file("/data/stage/openssl-3.5.0/demos/guide/chain.pem");
    sslctx.use_private_key_file("/data/stage/openssl-3.5.0/demos/guide/pkey.pem",
        boost::asio::ssl::context::file_format::pem);
    SSL_CTX_set_alpn_select_cb(sslctx.native_handle(), select_alpn_cb, &alpn);
    sslctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    // sslctx.set_default_verify_paths();

    quic::server server{io, sslctx};

    quic::endpoint addr { boost::asio::ip::make_address("127.0.0.1"), 8443 };
    server.listen(addr);
    for (;;) {
        quic::connection conn;
        std::cout << std::format("{:-^64}\n", "waiting for connection");
        server.accept(conn);
        std::cout << std::format("{:-^64}\n", "connection accepted");
        run(conn);
    }
    return 0;
}
