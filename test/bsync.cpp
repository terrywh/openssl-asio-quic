#include "../quic.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <iostream>


void run(boost::asio::io_context& io) {
    boost::asio::ssl::context ctx {SSL_CTX_new(OSSL_QUIC_client_method())};
    ctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    ctx.set_default_verify_paths();

    quic::application_protocol_list alpn {"http/1.0"};
    quic::connection conn {ctx, io.get_executor()};

    for (quic::endpoint addr : quic::resolve("localhost", "8443")) {
        std::cout << addr.to_string() << '\n';

        try {
            conn.connect(addr, "localhost", alpn);
        } catch(const std::exception& ex) {
            continue;
        } 
        break;
    }
    
    std::cout << "------------------- connection -----------------\n";
    ERR_print_errors_fp(stderr);
    std::cout << "------------------------------------------------\n";


    std::string payload {
        "GET /hello HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "\r\n"
    };

    try {
        quic::stream stream = conn.create_stream();
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


int main(int argc, char* argv[]) {
    boost::asio::io_context io;
    run(io);
    io.run();
    return 0;
}
