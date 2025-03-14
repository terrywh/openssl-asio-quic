#ifndef ASIO_QUIC_BASIC_CONNECTION_H
#define ASIO_QUIC_BASIC_CONNECTION_H

#include "detail/openssl.hpp"
#include "detail/connect.hpp"
#include "alpn.hpp"
#include "basic_endpoint.hpp"
#include "basic_stream.hpp"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/basic_datagram_socket.hpp>
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
    boost::asio::basic_datagram_socket<Protocol, Executor> socket_;
    // executor_type ex_;
    boost::asio::ssl::context& ctx_;
    SSL* conn_ = nullptr;
    

    template <class Executor1>
    basic_connection(const Executor1& ex, boost::asio::ssl::context& ctx, SSL* conn)
    : socket_(ex)
    , ctx_(ctx)
    , conn_(conn) {
        int fd = SSL_get_fd(conn_);
        BIO_sock_info_u info;
        BIO_sock_info(fd, BIO_sock_info_type::BIO_SOCK_INFO_ADDRESS, &info);
        if (BIO_ADDR_family(info.addr) == BOOST_ASIO_OS_DEF(AF_INET6)) {
            socket_ = boost::asio::basic_datagram_socket<proto>{ex, proto::v6(), fd};
        } else {
            socket_ = boost::asio::basic_datagram_socket<proto>{ex, proto::v4(), fd};
        }
    }

public:
    template <class Executor1>
    basic_connection(const Executor1& ex, boost::asio::ssl::context& ctx)
    : socket_(ex), ctx_(ctx) {}

    ~basic_connection() {
        if (conn_ != nullptr) SSL_free(conn_);
    }

    void connect(const endpoint_type& addr, const std::string& host, application_protocol_list& alpn) {
        socket_.connect(addr);

        // int socket = BIO_socket(BOOST_ASIO_OS_DEF(AF_INET), BOOST_ASIO_OS_DEF(SOCK_DGRAM), addr.protocol().protocol(), 0);
        // if (socket == -1) {
        //     throw boost::system::system_error(SSL_get_error(nullptr, socket), boost::asio::error::get_ssl_category());
        // }
        
        // if (!BIO_connect(socket, addr, 0)) {
        //     throw boost::system::system_error(SSL_get_error(nullptr, socket), boost::asio::error::get_ssl_category());
        // }

        BIO* bio = BIO_new(BIO_s_datagram());
        BIO_set_fd(bio, socket_.native_handle(), BIO_NOCLOSE);

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

    using do_connect = detail::do_connect<protocol_type, executor_type>;

    template <class CompletionToken>
    auto async_connect(const std::string& host, const endpoint_type& addr, application_protocol_list& alpn,
        CompletionToken&& token) -> decltype(
            boost::asio::async_compose<CompletionToken, void (boost::system::error_code)>(
                std::declval<do_connect>(), token, socket_)) {

        return boost::asio::async_compose<CompletionToken,void (boost::system::error_code)>(
            do_connect{conn_, ctx_, socket_, host, addr, alpn}, token, socket_);
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

    template <class Executor1, class CompletionToken>
    void async_create_stream(basic_stream<Protocol, Executor1>& stream, CompletionToken&& token) {
        if (stream.stream_ = SSL_new_stream(conn_, SSL_STREAM_FLAG_NO_BLOCK); stream.stream_ == nullptr) {
            int err = SSL_get_error(conn_, 0);
            if (err == SSL_ERROR_WANT_READ) {

            } else if (err == SSL_ERROR_WANT_WRITE) {

            } else {
                boost::asio::post(socket_.get_executor(), [err, callback = token] () {
                    callback(boost::system::error_code{err, boost::asio::error::get_ssl_category()});
                });
            }
        }
    }

    template <class Protocol1, class Executor1>
    friend class basic_server;
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_CONNECTION_H
