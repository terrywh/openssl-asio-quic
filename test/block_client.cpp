#include "../quic.hpp"
#include <format>
#include <iostream>

void run(boost::asio::io_context& io) {
    boost::asio::ssl::context sslctx {SSL_CTX_new(OSSL_QUIC_client_method())};
    sslctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    // sslctx.set_default_verify_paths();

    quic::connection conn {io, sslctx};
    conn.host("localhost");
    conn.alpn(quic::application_protocol_list {"http/1.0"});

    quic::connect(conn, quic::resolve("localhost", "8443"));

    std::cout << std::format("{:-^64}\n", " connection established ");

    std::string payload {
        "POST /hello HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "world"
    };

    quic::stream stream;
    conn.create_stream(stream);
    std::cout << std::format("{:-^64}\n", " stream created ");

    std::size_t size = stream.write_some(boost::asio::buffer(payload));
    std::cout << std::format("{:-^64}\n", " request wrote ");
    std::cout << "size = " << size << "\n";
    stream.shutdown(boost::asio::socket_base::shutdown_send);

    payload.resize(1024);
    size = stream.read_some(boost::asio::buffer(payload));
    payload.resize(size);
    std::cout << std::format("{:-^64}\n", " response read ");
    std::cout << "size = " << size << "\n";
    std::cout << payload << "\n";

DONE:
    std::cout << "done.\n";
}

int main(int argc, char* argv[]) {
    boost::asio::io_context io;
    try {
        run(io);
    } catch(const boost::system::system_error& ex) {
        std::cout << "system_error: " << ex.what() << "\n";
    } catch(const std::exception& ex) {
        std::cout << "exception: " << ex.what() << "\n";
    }
    io.run();
    return 0;
}
