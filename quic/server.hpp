#ifndef ASIO_QUIC_BASIC_SERVER_H
#define ASIO_QUIC_BASIC_SERVER_H

#include "detail/ssl.hpp"
#include "detail/asio.hpp"
#include "detail/ssl_extra_data.hpp"

#include "endpoint.hpp"

#include "impl/server.hpp"

namespace quic {

class server {
    impl::server* impl_;

public:
    server(boost::asio::io_context& io, boost::asio::ssl::context& ctx) {
        impl_ = detail::ssl_extra_data::emplace<impl::server>(
            SSL_new_listener(ctx.native_handle(), 0), io, ctx);
        if (impl_ == nullptr)
            throw std::runtime_error("failed to create ssl listener");
    }

    void bind(const endpoint& addr) {
        impl_->bind(addr);
    }
    void listen() {
        impl_->listen();
    }
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_SERVER_H
