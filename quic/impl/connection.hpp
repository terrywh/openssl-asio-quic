#ifndef QUIC_DETAIL_SOCKET_EVENT_H
#define QUIC_DETAIL_SOCKET_EVENT_H

#include "../detail/ssl.hpp"
#include "../detail/asio.hpp"
#include "../alpn.hpp"
#include "../proto.hpp"
#include "waitable.hpp"
#include <iostream>
#include <vector>

namespace quic {
namespace impl {

struct connection : public waitable {
    using executor_type = boost::asio::strand<boost::asio::io_context::executor_type>;

   
    boost::asio::ssl::context& sslctx_;

    application_protocol_list alpn_;
    std::string               host_;

    template <class Executor>
    connection(SSL* handle, const Executor& ex, boost::asio::ssl::context& ctx)
    : waitable(ex, handle)
    , sslctx_(ctx) {
        std::cout << "+connection\n";
        
        alpn(application_protocol_list{"default/1"});
        host("localhost");
    }
    ~connection() {
        std::cout << "~connection\n";
    }

    void alpn(const application_protocol_list& alpn) {
        alpn_ = alpn;
    }

    void host(const std::string& host) {
        host_ = host;
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_SOCKET_EVENT_H
