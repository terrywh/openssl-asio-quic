#include "../quic.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <iostream>


void run(boost::asio::io_context& io) {
    boost::asio::ssl::context sslctx {SSL_CTX_new(OSSL_QUIC_client_method())};
    sslctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    sslctx.set_default_verify_paths();

    quic::connection conn {io, sslctx};
    conn.set_host("localhost");
    conn.set_alpn(quic::application_protocol_list {"http/1.0"});

    quic::connect(conn, quic::resolve("localhost", "8443"));
    
    std::cout << "------------------- connection -----------------\n";
    ERR_print_errors_fp(stderr);
    std::cout << "------------------------------------------------\n";


    std::string payload {
        "GET /hello HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "\r\n"
    };

    try {
        quic::stream stream;
        conn.create_stream(stream);
        std::cout << "stream: \n";

        std::size_t size = stream.write_some(boost::asio::buffer(payload));
        std::cout << "write: \n";
        stream.shutdown(boost::asio::socket_base::shutdown_send);

        payload.resize(1024);
        size = stream.read_some(boost::asio::buffer(payload));
        payload.resize(size);
        std::cout << "read: (" << size << ")\n";

        std::cout << payload << "\n";
    } catch(const std::runtime_error& ex) {
        std::cout << "------------------- exception -------------------------\n";
        std::cout << ex.what() << "\n";
        ERR_print_errors_fp(stderr);
        std::cout << "-------------------------------------------------------\n";
        goto DONE;
    }

DONE:
    std::cout << "done.\n";
}

struct Demo {};

void CRYPTO_EX_free_cb (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
      int idx, long argl, void *argp) {
    
    if (!ptr) return;

    std::cout << "free\n";
    delete reinterpret_cast<Demo*>(ptr);
}

int CRYPTO_EX_dup_cb (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void **from_d, int idx, long argl, void *argp) {
        
        std::cout << "dup\n";
    return 1;
}

int CRYPTO_SSL_IDX;

int main(int argc, char* argv[]) {
    boost::asio::io_context io;
    run(io);
    io.run();
    return 0;
}
