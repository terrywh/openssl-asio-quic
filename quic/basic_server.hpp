#ifndef ASIO_QUIC_BASIC_SERVER_H
#define ASIO_QUIC_BASIC_SERVER_H

#include "detail/openssl.hpp"
#include "basic_connection.hpp"
#include <boost/system.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ssl/context.hpp>

namespace quic {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_server {
public:
    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = typename std::decay<Executor>::type;

private:
    executor_type ex_;
    boost::asio::ssl::context& ctx_;
    boost::asio::basic_datagram_socket<Protocol, Executor> socket_;
    SSL* listener_;

public:

    explicit basic_server(executor_type& ex, boost::asio::ssl::context& ctx, boost::asio::ip::basic_endpoint<Protocol> bind)
    : ex_(ex)
    , ctx_(ctx) {
        boost::asio::ip::udp::socket socket {ex, bind};
        if (listener_ = SSL_new_listener(ctx_.native_handle(), 0); listener_ == nullptr) {
            throw std::runtime_error("failed to create ssl listener");
        }
        SSL_set_fd(listener_, socket.native_handle());
        socket.release();
    }

    void listen() {
        if (int r = SSL_listen(listener_); r != SSL_ERROR_NONE) {
            throw boost::system::system_error(SSL_get_error(listener_, r), boost::asio::error::get_ssl_category());
        }
    }

    template <class Executor1>
    void accept(basic_connection<Protocol, Executor1>& conn) {
        ERR_clear_error();
        if (conn.conn_ = SSL_accept_connection(listener_, 0); conn.conn_ == nullptr) {
            throw std::runtime_error("failed to accept connection");
        }
        SSL_set_default_stream_mode(conn.conn_, SSL_DEFAULT_STREAM_MODE_NONE);
    }

    static int select(SSL* ssl, const unsigned char* out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg) {
        basic_server* self = static_cast<basic_server*>(arg);

        return 0;
    }
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_SERVER_H
