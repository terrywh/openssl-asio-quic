#ifndef ASIO_QUIC_BASIC_CONNECTION_H
#define ASIO_QUIC_BASIC_CONNECTION_H

#include "detail/asio.hpp"
#include "detail/ssl.hpp"
#include "detail/ssl_extra_data.hpp"

#include "alpn.hpp"
#include "endpoint.hpp"
#include "endpoint_resolve_result.hpp"
#include "stream.hpp"

#include "impl/connection.hpp"
#include "impl/connection_connect.hpp"
#include "impl/connection_create_stream.hpp"
#include "impl/connection_accept_stream.hpp"
#include "impl/stream.hpp"

namespace quic {
namespace impl {
    struct server;
} // namespace impl

class connection {
    // 客户端
    template <class CompletionToken>
    friend auto async_connect(connection& conn, const endpoint_resolve_result& eps, CompletionToken&& token);
    friend auto connect(connection& conn, const endpoint_resolve_result& addr);
    // 服务端
    friend class server;
    impl::connection* impl_ = nullptr;

public:
    using executor_type = impl::connection::executor_type;
    // connection() = default;
    connection(boost::asio::io_context& io, boost::asio::ssl::context& ctx, SSL* handle = nullptr)
    : connection(io.get_executor(), ctx, handle) {}
    template <class Executor>
    connection(const Executor& ex, boost::asio::ssl::context& ctx, SSL* handle = nullptr) {
        impl_ = detail::ssl_extra_data::emplace<impl::connection>(handle, ex, ctx);
    }
    connection(const connection& conn) = delete;
    connection(connection&& conn) noexcept
    : impl_(std::exchange(conn.impl_, nullptr)) {}
    ~connection() {
        if (impl_ != nullptr) SSL_free(impl_->handle_);
    }

    connection& operator=(const connection& conn) = delete;
    connection& operator=(connection&& conn) noexcept {
        std::swap(impl_, conn.impl_);
        return *this;
    }

    executor_type& get_executor() const {
        return impl_->strand_;
    }
    /**
     * 设置用于应用层的交互协议列表
     */
    void alpn(const application_protocol_list& alpn) {
        impl_->alpn(alpn);
    }
    /**
     * 目标域名
     */
    void host(const std::string& host) {
        impl_->host(host);
    }
    /**
     * 链接指定目标
     */
    void connect(const endpoint& addr) {
        impl::connection_connect{impl_, addr}();
    }
    template <class CompletionToken>
    auto async_connect(const endpoint& addr, CompletionToken&& token) {
        return boost::asio::async_compose<CompletionToken, void (boost::system::error_code)>(
            impl::connection_connect_async{impl_, addr}, token);
    }

    void create_stream(stream& s) {
        if (s.impl_ == nullptr)
            s = stream{impl_};
        impl::connection_create_stream{impl_, s.impl_}();
    }
    // 参考 async_connect 实现 async_create_stream
    template <class CompletionToken>
    auto async_create_stream(stream& s, CompletionToken&& token) {
        if (s.impl_ == nullptr)
            s = stream{impl_};
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
            impl::connection_create_stream_async{impl_, s.impl_}, token);
    }
    void accept_stream(stream& s) {
        if (s.impl_ == nullptr)
            s = stream{impl_};
        impl::connection_accept_stream{impl_, s.impl_}();
    }

    // TODO shutdown()
    // TODO async_shutdown()
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_CONNECTION_H
