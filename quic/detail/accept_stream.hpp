#ifndef QUIC_DETAIL_ACCEPT_STREAM_H
#define QUIC_DETAIL_ACCEPT_STREAM_H

#include "connection_base.hpp"
#include "stream_base.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor>
struct accept_stream_impl {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;

    connection_type& conn_;
    stream_type& stream_;

    enum {starting, connecting, configuring, handshaking, done} state_;
    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
        if (error) {
            self.complete(error);
            return;
        }
        if (stream_.ssl_ = SSL_accept_stream(conn_.ssl_, 0); stream_.ssl_ == nullptr) {
            conn_.handle_ssl_error(SSL_get_error(conn_.ssl_, 0), std::move(self));
            return;
        }
        self.complete(error);
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_ACCEPT_STREAM_H
