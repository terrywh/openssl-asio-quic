#ifndef ASIO_QUIC_BASIC_CONNECTION_H
#define ASIO_QUIC_BASIC_CONNECTION_H

#include "detail/asio.hpp"
#include "detail/ssl.hpp"
#include "detail/connection_base.hpp"
#include "detail/do_connect.hpp"
#include "detail/do_create_stream.hpp"
#include "alpn.hpp"
#include "basic_endpoint.hpp"
#include "basic_stream.hpp"

#include <boost/core/demangle.hpp>
#include <iostream>

namespace quic {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_connection {
    template <class Protocol1, class Executor1, class CompletionToken>
    friend auto async_connect(basic_connection<Protocol1, Executor1>& conn,
        const basic_endpoints<Protocol1>& addr, CompletionToken&& token);

    template <class Protocol1, class Executor1>
    friend auto connect(basic_connection<Protocol1, Executor1>& conn,
        const basic_endpoints<Protocol1>& addr);

    using executor_type = typename detail::connection_base<Protocol,Executor>::executor_type;
    using endpoint_type = typename detail::connection_base<Protocol,Executor>::endpoint_type;
    using stream_type = basic_stream<Protocol, Executor>;

private:
    detail::connection_base<Protocol, Executor>* base_;

    template <class ExecutorContext>
    basic_connection(ExecutorContext& ex, boost::asio::ssl::context& ctx, SSL* ssl)
    : base_(new detail::connection_base<Protocol, Executor>(ex, ctx, ssl)) {
        
    }

public:
    basic_connection(basic_connection&& conn) = delete;
    basic_connection(const basic_connection& conn) = delete;

    template <class ExecutorContext>
    basic_connection(ExecutorContext& ex, boost::asio::ssl::context& ctx)
    : base_(new detail::connection_base<Protocol, Executor>(ex, ctx)) { }

    SSL* native_handle() const {
        return base_->ssl_;
    }

    ~basic_connection() {
        base_->del_ref();
    }
    /**
     * 设置用于应用层的交互协议列表
     */
    void set_alpn(const application_protocol_list& alpn) {
        base_->set_alpn(alpn);
    }
    /**
     * 目标域名
     */
    void set_host(const std::string& host) {
        base_->set_host(host);
    }

    void connect(const endpoint_type& addr) {
        detail::do_connect{base_, addr}();
    }

    template <class CompletionToken>
    auto async_connect(const endpoint_type& addr, CompletionToken&& token) {
        return boost::asio::async_compose<CompletionToken, void (boost::system::error_code)>(
            detail::do_async_connect{base_, addr}, token);
    }

    // accept_stream(stream_type& stream) {
    //     stream.base_ = new detail::stream_base<Protocol, Executor>(base_);
    //     if (stream.base_->handle_ = SSL_accept_stream(base_->ssl_, 0); stream.base_->handle_ == nullptr) {
    //         throw boost::system::system_error(SSL_get_error(base_->ssl_, 0), boost::asio::error::get_ssl_category());
    //     }
    // }

    void create_stream(stream_type& stream) {
        stream.base_ = new detail::stream_base<Protocol, Executor>(base_);
        detail::do_create_stream{base_, stream.base_}();
    }

    // 参考 async_connect 实现 async_create_stream
    template <class CompletionToken>
    auto async_create_stream(stream_type& stream, CompletionToken&& token) {
        stream.base_ = new detail::stream_base<Protocol, Executor>();
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, stream_type)>(
            detail::do_async_create_stream{base_, stream.base_}, token);
    }

    template <class Protocol1, class Executor1>
    friend class basic_server;
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_CONNECTION_H
