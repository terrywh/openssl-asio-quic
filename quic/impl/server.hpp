#ifndef QUIC_IMPL_BASIC_SERVER_H
#define QUIC_IMPL_BASIC_SERVER_H

#include "../detail/asio.hpp"
#include "../detail/ssl.hpp"
#include "../detail/error_handler.hpp"

#include "../proto.hpp"
#include "../endpoint.hpp"
#include "../alpn.hpp"

#include <iostream>

namespace quic {
namespace impl {

struct server: public waitable {
    boost::asio::ssl::context& sslctx_;
    application_protocol_list alpn_;

    template <class Executor>
    server(SSL* handle, const Executor& ex, boost::asio::ssl::context& ctx)
    : waitable(ex, handle)
    , sslctx_(ctx) {
        std::cout << "+basic_server\n";
        alpn(application_protocol_list{"default/1"});
    }
    ~server() {
        std::cout << "-basic_server\n";
    }

    void bind(const endpoint& addr) {
        socket_.open(addr.protocol());
        socket_.bind(addr);
        BOOST_ASSERT(socket_.is_open());
        SSL_set_fd(handle_, socket_.native_handle());
    }
    void listen() {
        if (!SSL_listen(handle_))
            detail::error_handler(SSL_get_error(handle_, 0)).throws();
    }

    void alpn(const application_protocol_list& alpn) {
        alpn_ = alpn;
    }
};

} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_BASIC_SERVER_H
