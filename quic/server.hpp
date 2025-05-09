#ifndef ASIO_QUIC_BASIC_SERVER_H
#define ASIO_QUIC_BASIC_SERVER_H

#include "detail/ssl.hpp"
#include "detail/asio.hpp"
#include "basic_endpoint.hpp"
#include "impl/handler.hpp"
#include "impl/server.hpp"

namespace quic {

class server: public impl::handler {
public:
private:
    SSL*       handler_;
    impl::server* impl_;

public:
    server(boost::asio::io_context& io, boost::asio::ssl::context& ctx) {
        if (handler_ = SSL_new_listener(ctx.native_handle(), 0); handler_ == nullptr) {
            throw std::runtime_error("failed to create ssl listener");
        }
        impl_ = emplace<impl::server>(handler_, io, ctx);
    }

    template <class Protocol>
    void bind(const basic_endpoint<Protocol>& addr) {
        impl_->bind(handler_, addr);
    }

    ~server() {
        SSL_free(handler_); // 引用计数释放关联实现
    }
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_SERVER_H
