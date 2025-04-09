#ifndef ASIO_QUIC_BASIC_CONNECTION_H
#define ASIO_QUIC_BASIC_CONNECTION_H

#include "detail/asio.hpp"
#include "detail/ssl.hpp"
#include "detail/connection_base.hpp"
#include "detail/do_connect.hpp"
#include "alpn.hpp"
#include "basic_endpoint.hpp"
#include "basic_stream.hpp"

#include <boost/core/demangle.hpp>
#include <iostream>

namespace quic {

template <class Protocol, class Executor = boost::asio::any_io_executor>
class basic_connection : public detail::connection_base<Protocol, Executor> {

    using executor_type = typename detail::connection_base<Protocol,Executor>::executor_type;
    using endpoint_type = typename detail::connection_base<Protocol,Executor>::endpoint_type;
    using stream_type = basic_stream<Protocol, Executor>;

private:
    template <class ExecutorContext>
    basic_connection(boost::asio::ssl::context& ctx, ExecutorContext& ex, SSL* conn)
    : detail::connection_base<Protocol, Executor>(ctx, ex, conn) { }

public:
    basic_connection(basic_connection&& conn) = delete;
    basic_connection(const basic_connection& conn) = delete;

    template <class ExecutorContext>
    basic_connection(boost::asio::ssl::context& ctx, ExecutorContext& ex)
    : detail::connection_base<Protocol, Executor>(ctx, ex, static_cast<SSL*>(nullptr)) { }

    void connect(const endpoint_type& addr, const std::string& host, application_protocol_list& alpn) {
        this->socket_.connect(addr);
        this->create_ssl(addr, host, alpn, false);
        // TLS 协议握手
        if (int r = SSL_connect(this->ssl_); r <= 0) {
            throw boost::system::system_error(SSL_get_error(this->ssl_, r), boost::asio::error::get_ssl_category());
        }
    }

    template <class CompletionToken>
    auto async_connect(const std::string& host, const endpoint_type& addr, application_protocol_list& alpn,
        CompletionToken&& token) {

        return boost::asio::async_initiate<CompletionToken, void (boost::system::error_code)>(
            [] (auto&& handler, detail::connection_base<Protocol, Executor>& conn, const endpoint_type& addr, const std::string& host, application_protocol_list& alpn) {
                detail::do_connect<Protocol, Executor, decltype(handler)>{std::move(handler), conn, addr, host, alpn}({});
            }, std::move(token), std::ref(*this), std::ref(addr), std::ref(host), std::ref(alpn));
    }

    stream_type accept_stream() {
        if (SSL* stream = SSL_accept_stream(this->ssl_, 0); stream == nullptr) {
            throw boost::system::system_error(SSL_get_error(this->ssl_, 0), boost::asio::error::get_ssl_category());
        } else {
            return {*this, stream};
        }
    }

    // using do_accept_stream = detail::accept_stream_impl<protocol_type, executor_type>;
    // template <class CompletionToken>
    // auto async_accept_stream(basic_stream<Protocol, Executor>& stream, CompletionToken&& token) -> decltype(
    //     boost::asio::async_compose<CompletionToken, void(boost::system::error_code, stream_type)>(
    //         std::declval<do_accept_stream>(), token, this->socket_)) {
        
    //     return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, stream_type)>(
    //         do_accept_stream{*this->conn_, stream}, token, this->socket_);
    // }

    stream_type create_stream() {
        if (SSL* ssl = SSL_new_stream(this->ssl_, 0); ssl == nullptr) {
            throw boost::system::system_error(SSL_get_error(this->ssl_, 0), boost::asio::error::get_ssl_category());
        } else {
            return {*this, ssl};
        }
    }

    // using do_create_stream = detail::create_stream_impl<protocol_type, executor_type>;

    // template <class Executor1, class CompletionToken>
    // auto async_create_stream(basic_stream<Protocol, Executor1>& stream, CompletionToken&& token) ->
    //     decltype(boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
    //         std::declval<do_create_stream>(), this->socket_
    //     )) {
    //     return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
    //         do_create_stream{*this, stream}, this->socket_);
    // }

    template <class Protocol1, class Executor1>
    friend class basic_server;
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_CONNECTION_H
