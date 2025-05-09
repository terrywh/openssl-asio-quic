#ifndef ASIO_QUIC_BASIC_SERVER_H
#define ASIO_QUIC_BASIC_SERVER_H

#include "detail/ssl.hpp"
#include "detail/asio.hpp"
#include "detail/attached.hpp"
#include "basic_endpoint.hpp"
#include "impl/basic_server.hpp"

namespace quic {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_server: public detail::attached< impl::basic_server<Protocol, Executor> > {
public:
    using protocol_type = typename std::decay<Protocol>::type;
    using executor_type = typename std::decay<Executor>::type;
    using implement_type = impl::basic_server<Protocol, Executor>;
private:
    SSL*         handler_;
    implement_type* impl_;

public:
    template <class ExecutionContext>
    basic_server(ExecutionContext& ex, boost::asio::ssl::context& ctx) {
        if (handler_ = SSL_new_listener(ctx.native_handle(), 0); handler_ == nullptr) {
            throw std::runtime_error("failed to create ssl listener");
        }
        impl_ = detail::attached<implement_type>::emplace_attached(handler_, ex, ctx);
    }

    void bind(const basic_endpoint<Protocol>& addr) {
        impl_->bind(handler_, addr);
    }

    ~basic_server() {
        SSL_free(handler_); // 引用计数释放关联实现
    }
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_SERVER_H
