#ifndef QUIC_IMPL_BASIC_SERVER_H
#define QUIC_IMPL_BASIC_SERVER_H

#include "../detail/asio.hpp"
#include "../detail/ssl.hpp"
#include "../basic_endpoint.hpp"
#include <iostream>

namespace quic {
namespace impl {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_server {
public:
    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = typename std::decay<Executor>::type;

private:
    boost::asio::strand<Executor>                          strand_;
    boost::asio::ssl::context&                                ctx_;
    boost::asio::basic_datagram_socket<Protocol, Executor> socket_;

public:
    template <class ExecutionContext>
    basic_server(ExecutionContext& ex, boost::asio::ssl::context& ctx)
    : strand_(ex.get_executor())
    , ctx_(ctx)
    , socket_(strand_)  {
        std::cout << "+basic_server\n";
    }
    ~basic_server() {
        std::cout << "-basic_server\n";
    }

    void bind(SSL* handler, const basic_endpoint<Protocol>& addr) {
        socket_.open(addr.protocol());
        socket_.bind(addr);
        SSL_set_fd(handler, socket_.native_handle());
    }

    void listen(SSL* handler) {
        if (int r = SSL_listen(handler); r != SSL_ERROR_NONE) {
            throw boost::system::system_error(SSL_get_error(handler, r), boost::asio::error::get_ssl_category());
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
