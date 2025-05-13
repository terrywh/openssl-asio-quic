#ifndef QUIC_IMPL_CONNECTION_ACCEPT_STREAM_H
#define QUIC_IMPL_CONNECTION_ACCEPT_STREAM_H

#include "../detail/error_handler.hpp"
#include "../detail/ssl_extra_data.hpp"
#include "connection.hpp"
#include "stream.hpp"

namespace quic {
namespace impl {

struct connection_accept_stream {
    impl::connection* conn_;
    impl::stream*   stream_;

    connection_accept_stream(impl::connection* conn, impl::stream* stream)
    : conn_(conn)
    , stream_(stream) { }

    void operator()() const {
        if (stream_->handle_ = SSL_accept_stream(conn_->handle_, 0); stream_->handle_ == nullptr)
            detail::error_handler(SSL_get_error(conn_->handle_, 0)).throws();
        detail::ssl_extra_data::set<impl::stream>(stream_->handle_, stream_);
    }
};

struct connection_accept_stream_async {
    impl::connection* conn_;
    impl::stream*   stream_;

    connection_accept_stream_async(impl::connection* conn, impl::stream* stream)
    : conn_(conn)
    , stream_(stream) { }

    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
        if (error) {
            self.complete(error);
            return;
        }
        if (stream_->handle_ = SSL_new_stream(conn_->handle_, SSL_STREAM_FLAG_NO_BLOCK); stream_->handle_ == nullptr) {
            if (detail::error_handler(SSL_get_error(conn_->handle_, 0)).wait(self))
                conn_->async_wait(std::move(self));
            return;
        }
        detail::ssl_extra_data::set<impl::stream>(stream_->handle_, stream_);
        self.complete(error);
    }
};


} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_CONNECTION_ACCEPT_STREAM_H
