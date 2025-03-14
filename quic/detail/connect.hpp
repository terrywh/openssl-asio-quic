#ifndef QUIC_DETAIL_CONNECT_H
#define QUIC_DETAIL_CONNECT_H

#include "../basic_endpoint.hpp"
#include "../alpn.hpp"
#include <boost/asio/basic_datagram_socket.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/compose.hpp>

namespace quic {
namespace detail {

template <class Protocol, class Executor>
struct do_connect {
    using socket_type = boost::asio::basic_datagram_socket<Protocol, Executor>;
    SSL*& conn_;
    boost::asio::ssl::context& ctx_;
    socket_type& socket_;
    const std::string& host_;
    const basic_endpoint<Protocol>&  addr_;
    application_protocol_list& alpn_;

    enum {starting, connecting, configuring, handshaking, done} state_;
    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
CONTINUE:
        switch(state_) {
        case starting:
            state_ = connecting;
            socket_.async_connect(addr_, std::move(self));
            break;
        case connecting:
            if (error) {
                self.complete(error);
                return;
            }
            state_ = configuring;
            socket_.native_non_blocking(true);
            {
                BIO* bio = BIO_new(BIO_s_datagram());
                BIO_set_fd(bio, socket_.native_handle(), BIO_NOCLOSE);

                conn_ = SSL_new(ctx_.native_handle());
                SSL_set_bio(conn_, bio, bio);
            }
            SSL_set_default_stream_mode(conn_, SSL_DEFAULT_STREAM_MODE_NONE);
            SSL_set_blocking_mode(conn_, 0);

            SSL_set_tlsext_host_name(conn_, host_.c_str());
            SSL_set1_host(conn_, host_.c_str());
            SSL_set_alpn_protos(conn_, alpn_, alpn_.size());
            SSL_set1_initial_peer_addr(conn_, addr_);

            state_ = handshaking;
            goto CONTINUE;
            break;
        case handshaking:
            if (error) {
                self.complete(error);
                return;
            }
            if (int r = SSL_connect(conn_); r <= 0) {
                int err = SSL_get_error(conn_, r);
                switch (err) {
                case SSL_ERROR_WANT_READ:
                    socket_.async_wait(socket_type::wait_read, std::move(self));
                    break;
                case SSL_ERROR_WANT_WRITE:
                    socket_.async_wait(socket_type::wait_write, std::move(self));
                    break;
                default:
                    self.complete(boost::system::error_code{err, boost::asio::error::get_ssl_category()});
                }
            } else {
                self.complete(error);
            }
        }
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CONNECT_H
