#include "../quic.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
// #include <boost/asio/read_until.hpp>
// #include <boost/asio/buffer.hpp>
#include <iostream>
#include <format>

boost::asio::awaitable<void> run(boost::asio::io_context& io) {
    boost::asio::ssl::context sslctx {SSL_CTX_new(OSSL_QUIC_client_method())};
    sslctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    sslctx.set_default_verify_paths();

    quic::connection conn {io, sslctx};
    conn.set_host("localhost");
    conn.set_alpn(quic::application_protocol_list {"http/1.0"});

    co_await quic::async_connect(conn, quic::resolve("localhost", "8443"),
        boost::asio::use_awaitable);
    std::cout << std::format("{:-^64}\n", " connection established ");

    std::string payload {
        "POST /hello HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "world"
    };

    quic::stream stream;
    co_await conn.async_create_stream(stream, boost::asio::use_awaitable);
    std::cout << std::format("{:-^64}\n", " stream created ");

    std::size_t size = co_await stream.async_write_some(boost::asio::buffer(payload), boost::asio::use_awaitable);
    std::cout << std::format("{:-^64}\n", " request wrote ");
    stream.shutdown(boost::asio::socket_base::shutdown_send);

    payload.resize(1024);
    size = co_await stream.async_read_some(boost::asio::buffer(payload), boost::asio::use_awaitable);
    payload.resize(size);

    std::cout << std::format("{:-^64}\n", " response read ");
    std::cout << payload << "\n";

DONE:
    co_return;
}


int main(int argc, char* argv[]) {
    boost::asio::io_context io;

    boost::asio::co_spawn(io, run(io), [](std::exception_ptr e){
        try {
            if (e) std::rethrow_exception(e);
        } catch(const boost::system::system_error& ex) {
            std::cout << "system_error: (" << ex.what() << "\n";
        } catch(const std::exception& ex) {
            std::cout << "exception: " << ex.what() << "\n";
        }
    });
    io.run();
    std::cout << "done.\n";

    return 0;
}
