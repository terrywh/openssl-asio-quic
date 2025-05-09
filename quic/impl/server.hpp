#ifndef QUIC_IMPL_BASIC_SERVER_H
#define QUIC_IMPL_BASIC_SERVER_H

#include "../detail/asio.hpp"
#include "../detail/ssl.hpp"
#include "../proto.hpp"
#include "../endpoint.hpp"
#include <iostream>

namespace quic {
namespace impl {

struct server {
    SSL*                                                        handle_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    boost::asio::ssl::context&                                  sslctx_;
    boost::asio::basic_datagram_socket<quic::proto>             socket_;

    server(SSL* handle, boost::asio::io_context& io, boost::asio::ssl::context& ctx)
    : handle_(handle)
    , strand_(io.get_executor())
    , sslctx_(ctx)
    , socket_(strand_)  {
        std::cout << "+basic_server\n";
    }
    ~server() {
        std::cout << "-basic_server\n";
    }

    void bind(endpoint addr) {
        socket_.open(addr.protocol());
        socket_.bind(addr);
        SSL_set_fd(handle_, socket_.native_handle());
    }

    void listen() {
        if (int r = SSL_listen(handle_); r != SSL_ERROR_NONE) {
            throw boost::system::system_error(SSL_get_error(handle_, r), boost::asio::error::get_ssl_category());
        }
    }

    // template <class Executor1>
    // void accept(basic_connection<Protocol, Executor1>& conn) {
    //     ERR_clear_error();
    //     if (conn.conn_ = SSL_accept_connection(listener_, 0); conn.conn_ == nullptr) {
    //         throw std::runtime_error("failed to accept connection");
    //     }
    //     SSL_set_default_stream_mode(conn.conn_, SSL_DEFAULT_STREAM_MODE_NONE);
    // }

    // static int select(SSL* ssl, const unsigned char* out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg) {
    //     basic_server* self = static_cast<basic_server*>(arg);

    //     return 0;
    // }
};

} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_BASIC_SERVER_H
