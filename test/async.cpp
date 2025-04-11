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
    boost::asio::ssl::context ctx {SSL_CTX_new(OSSL_QUIC_client_method())};
    ctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    ctx.set_default_verify_paths();

    quic::connection conn {ctx, io};
    conn.set_alpn(quic::application_protocol_list {"http/1.0"});
    conn.set_host("localhost");

    for (quic::endpoint addr : quic::resolve("localhost", "8443")) {
        std::cout << addr.to_string() << '\n';

        // try {
        //     conn.connect(addr, "localhost", alpn);
        // } catch(const std::exception& ex) {
        //     continue;
        // } 
        std::cout << std::chrono::system_clock::now() << " before connect\n";
        try {
            co_await conn.async_connect(addr, boost::asio::use_awaitable);
        }catch(std::exception& ex) {
            std::cout << "exception1: " << ex.what() << "\n";
        }
        std::cout << std::chrono::system_clock::now() << " after connect\n";
        break;
    }
    
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

    boost::asio::co_spawn(io, run(io), [](std::exception_ptr e){ if (e) std::rethrow_exception(e); });
    io.run();
    std::cout << "done.\n";

    return 0;
}
