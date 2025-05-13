#include "../quic.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

boost::asio::awaitable<void> run_conn(quic::connection conn) {
    quic::stream stream;
    std::cout << std::format("{:-^64}\n", "waiting for stream");
    conn.accept_stream(stream);
    std::cout << std::format("{:-^64}\n", "stream accepted");
  
    std::string payload;
    payload.resize(1024);
    std::size_t size = stream.read_some(boost::asio::buffer(payload));
    payload.resize(size);
    std::cout << std::format("{:-^64}\n", " request read ");
    std::cout << "size = " << size << "\n";
    std::cout << payload << "\n";

    size = stream.write_some(boost::asio::buffer(payload));
    std::cout << std::format("{:-^64}\n", " response wrote ");
    std::cout << "size = " << size << "\n";
    stream.shutdown(boost::asio::socket_base::shutdown_send);

DONE:
    co_return;
}

boost::asio::awaitable<void> run(boost::asio::io_context& io) {
    boost::asio::ssl::context sslctx {SSL_CTX_new(OSSL_QUIC_server_method())};
    sslctx.use_certificate_chain_file("/data/stage/openssl-3.5.0/demos/guide/chain.pem");
    sslctx.use_private_key_file("/data/stage/openssl-3.5.0/demos/guide/pkey.pem",
        boost::asio::ssl::context::file_format::pem);
    sslctx.set_verify_mode(boost::asio::ssl::context_base::verify_none);
    // sslctx.set_default_verify_paths();

    quic::server server{io, sslctx};
    server.alpn(quic::application_protocol_list {"http/1.0"});
    server.listen({ boost::asio::ip::make_address("127.0.0.1"), 8443 });
    for (;;) {
        quic::connection conn{io, sslctx};
        std::cout << std::format("{:-^64}\n", "waiting for connection");
        co_await server.async_accept(conn, boost::asio::use_awaitable);
        std::cout << std::format("{:-^64}\n", "connection accepted");
        boost::asio::co_spawn(conn.get_executor(), run_conn(std::move(conn)), boost::asio::detached);
    }

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
