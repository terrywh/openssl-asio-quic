#ifndef QUIC_IMPL_SERVER_ACCEPT_H
#define QUIC_IMPL_SERVER_ACCEPT_H

#include "../detail/ssl.hpp"
#include "../detail/error_handler.hpp"
#include "../detail/ssl_extra_data.hpp"
#include "connection.hpp"

namespace quic {
namespace impl {

struct server_accept {
    impl::server*     impl_;
    impl::connection* conn_;

    server_accept(impl::server* impl, impl::connection* conn)
    : impl_(impl)
    , conn_(conn) {}

    void operator()() {
        if (SSL* handle = SSL_accept_connection(impl_->handle_, 0); handle == nullptr) {
            detail::error_handler(SSL_get_error(impl_->handle_, 0)).throws();
        } else {
            detail::ssl_extra_data::set<impl::connection>(handle, conn_);
            conn_->handle_ = handle;
        }
    }
};

struct server_accept_async {
    impl::server*     impl_;
    impl::connection* conn_;

    server_accept_async(impl::server* impl, impl::connection* conn)
    : impl_(impl)
    , conn_(conn) {}

    template <class Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
        if (error) {
            self.complete(error);
            return;
        }
        SSL* handle = SSL_accept_connection(impl_->handle_, SSL_ACCEPT_CONNECTION_NO_BLOCK);
        if (handle == nullptr) {
            impl_->async_wait(std::move(self));
            return;
        }
        detail::ssl_extra_data::set<impl::connection>(handle, conn_);
        conn_->handle_ = handle;
        self.complete(error);
    }
};

} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_SERVER_ACCEPT_H