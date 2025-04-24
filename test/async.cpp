#include "../quic.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/function.hpp>
#include <iostream>

static std::string payload {
    "GET /hello HTTP/1.0\r\n"
    "Host: localhost\r\n"
    "\r\n"
};

boost::asio::awaitable<void> run(boost::asio::io_context& io) {
    boost::asio::ssl::context sslctx {SSL_CTX_new(OSSL_QUIC_client_method())};
    sslctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    sslctx.set_default_verify_paths();

    quic::connection conn {io, sslctx};
    conn.set_alpn(quic::application_protocol_list {"http/1.0"});
    conn.set_host("localhost");

    auto es = quic::resolve("localhost", "8443");
    co_await quic::async_connect(conn, es, boost::asio::use_awaitable);
    
    std::cout << "------------------- connection ------------------------\n";
    ERR_print_errors_fp(stderr);
    std::cout << "-------------------------------------------------------\n";

    // try {
    //     quic::stream stream = conn.create_stream();
    //     std::cout << "stream: \n";

    //     std::size_t size = stream.write_some(boost::asio::buffer(payload));
    //     std::cout << "write: \n";
    //     stream.shutdown(boost::asio::socket_base::shutdown_send);

    //     payload.resize(1024);
    //     size = stream.read_some(boost::asio::buffer(payload));
    //     payload.resize(size);
    //     std::cout << "read: (" << size << ")\n";

    //     std::cout << payload << "\n";
    // } catch(const std::runtime_error& ex) {
    //     std::cout << "------------------- exception -------------------------\n";
    //     std::cout << ex.what() << "\n";
    //     ERR_print_errors_fp(stderr);
    //     std::cout << "-------------------------------------------------------\n";
    //     goto DONE;
    // }

DONE:
    co_return;
}


int main(int argc, char* argv[]) {
    boost::asio::io_context io;

    boost::asio::co_spawn(io, run(io), [](std::exception_ptr e){
        try {
            if (e) std::rethrow_exception(e);
        } catch(const std::exception& ex) {
            std::cout << "exception: " << ex.what() << "\n";
        }
    });
    io.run();
    std::cout << "done.\n";

    return 0;
}
