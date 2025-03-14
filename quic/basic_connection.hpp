#ifndef ASIO_QUIC_BASIC_CONNECTION_H
#define ASIO_QUIC_BASIC_CONNECTION_H

#include "detail/openssl.hpp"
#include "alpn.hpp"
#include "basic_endpoint.hpp"
#include "basic_stream.hpp"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/udp.hpp>

namespace quic {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_connection {
public:
    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = typename std::decay<Executor>::type;
    using endpoint_type = basic_endpoint<Protocol>;

private:
    executor_type ex_;
    boost::asio::ssl::context& ctx_;
    SSL* conn_ = nullptr;

    template <class Executor1>
    basic_connection(const Executor1& ex, boost::asio::ssl::context& ctx, SSL* conn)
    : ex_(ex), ctx_(ctx), conn_(conn) {}

public:
    template <class Executor1>
    basic_connection(const Executor1& ex, boost::asio::ssl::context& ctx)
    : ex_(ex), ctx_(ctx) {}

    ~basic_connection() {
        if (conn_ != nullptr) SSL_free(conn_);
    }

    void connect(const endpoint_type& addr, const std::string& host, application_protocol_list& alpn) {
        int socket = BIO_socket(BOOST_ASIO_OS_DEF(AF_INET), BOOST_ASIO_OS_DEF(SOCK_DGRAM), addr.protocol().protocol(), 0);
        if (socket == -1) {
            throw boost::system::system_error(SSL_get_error(nullptr, socket), boost::asio::error::get_ssl_category());
        }
        
        if (!BIO_connect(socket, addr, 0)) {
            throw boost::system::system_error(SSL_get_error(nullptr, socket), boost::asio::error::get_ssl_category());
        }

        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, socket, BIO_CLOSE);

        conn_ = SSL_new(ctx_.native_handle());
        SSL_set_default_stream_mode(conn_, SSL_DEFAULT_STREAM_MODE_NONE);
        SSL_set_bio(conn_, bio, bio);

        SSL_set_tlsext_host_name(conn_, host.c_str());
        SSL_set1_host(conn_, host.c_str());
        SSL_set_alpn_protos(conn_, alpn, alpn.size());
        SSL_set1_initial_peer_addr(conn_, addr);

        // TLS 协议握手
        if (int r = SSL_connect(conn_); r <= 0) {
            if (r = SSL_get_verify_result(conn_); r != X509_V_OK) {
                throw std::runtime_error(X509_verify_cert_error_string(r));
            } else {
                throw std::runtime_error(ERR_lib_error_string(ERR_get_error()));
            }
        }
    }

    template <class Executor1>
    void accept_stream(basic_stream<Protocol, Executor1>& stream) {
        if (stream.stream_ = SSL_accept_stream(conn_, 0); stream.stream_ == nullptr) {
            throw std::runtime_error("failed to accept stream");
        }
    }

    template <class Executor1>
    void create_stream(basic_stream<Protocol, Executor1>& stream) {
        if (stream.stream_ = SSL_new_stream(conn_, 0); stream.stream_ == nullptr) {
            throw std::runtime_error("failed to create stream");
        }
    }

    template <class Protocol1, class Executor1>
    friend class basic_server;
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_CONNECTION_H
