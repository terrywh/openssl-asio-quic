#ifndef ASIO_QUIC_BASIC_SERVER_H
#define ASIO_QUIC_BASIC_SERVER_H

#include "detail/ssl.hpp"
#include "detail/asio.hpp"
#include "detail/ssl_extra_data.hpp"
#include "detail/error_handler.hpp"

#include "endpoint.hpp"
#include "connection.hpp"

#include "impl/server.hpp"

namespace quic {

class server {
    impl::server* impl_;

public:
    server(boost::asio::io_context& io, boost::asio::ssl::context& ctx)
    : server(io.get_executor(), ctx) {}
    template <class Executor>
    server(const Executor& ex, boost::asio::ssl::context& ctx) {
        impl_ = detail::ssl_extra_data::emplace<impl::server>(
            SSL_new_listener(ctx.native_handle(), 0), ex, ctx);
        if (impl_ == nullptr)
            throw std::runtime_error("failed to create ssl listener");
    }
    ~server() {
        SSL_free(impl_->handle_);
    }
    
    void listen(const endpoint& addr) {
        impl_->bind(addr);
        impl_->listen();
    }
    void accept(quic::connection& conn) {
        ERR_clear_error();
        if (SSL* handle = SSL_accept_connection(impl_->handle_, 0); handle == nullptr) {
            detail::error_handler(SSL_get_error(impl_->handle_, 0)).throws();
        } else {
            conn = quic::connection{impl_->strand_.get_inner_executor(), impl_->sslctx_, handle};
        }
    }
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_SERVER_H
