#ifndef ASIO_QUIC_BASIC_SERVER_H
#define ASIO_QUIC_BASIC_SERVER_H

#include "detail/ssl.hpp"
#include "detail/asio.hpp"
#include "detail/ssl_extra_data.hpp"
#include "detail/error_handler.hpp"

#include "endpoint.hpp"
#include "connection.hpp"

#include "impl/server.hpp"
#include "impl/server_accept.hpp"

namespace quic {

class server {
    impl::server* impl_;
    
    static int select_alpn_cb(SSL *ssl, const unsigned char **out,
                        unsigned char *out_len, const unsigned char *in,
                        unsigned int in_len, void *arg) {
        impl::server* impl = static_cast<impl::server*>(arg);
        if (SSL_select_next_proto((unsigned char **)out, out_len, impl->alpn_, impl->alpn_.size(), in, in_len) == OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_OK;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
public:
    server(boost::asio::io_context& io, boost::asio::ssl::context& ctx)
    : server(io.get_executor(), ctx) {}
    template <class Executor>
    server(const Executor& ex, boost::asio::ssl::context& ctx) {
        impl_ = detail::ssl_extra_data::emplace<impl::server>(
            SSL_new_listener(ctx.native_handle(), 0), ex, ctx);
        if (impl_ == nullptr)
            throw std::runtime_error("failed to create ssl listener");
        SSL_CTX_set_alpn_select_cb(ctx.native_handle(), select_alpn_cb, impl_);
    }
    ~server() {
        SSL_free(impl_->handle_);
    }
    
    void alpn(const application_protocol_list& alpn) {
        impl_->alpn(alpn);
    }

    void listen(const endpoint& addr) {
        impl_->bind(addr);
        impl_->listen();
    }

    void accept(quic::connection& conn) {
        ERR_clear_error();
        impl::server_accept{impl_, conn.impl_}();
    }
    template <class CompletionToken>
    auto async_accept(quic::connection& conn, CompletionToken&& token) {
        ERR_clear_error();
        return boost::asio::async_compose<CompletionToken, void (boost::system::error_code)>(
            impl::server_accept_async{impl_, conn.impl_}, token);
    }
};

} // namespace quic

#endif // ASIO_QUIC_BASIC_SERVER_H
