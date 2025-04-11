#ifndef QUIC_DETAIL_CONNECT_H
#define QUIC_DETAIL_CONNECT_H

#include "connection_base.hpp"
#include "../basic_endpoint.hpp"
#include "../alpn.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor, class Handler>
struct do_connect {
    using handler_type = typename std::decay<Handler>::type;
    using endpoint_type = typename connection_base<Protocol, Executor>::endpoint_type;

    handler_type handler_;
    connection_base<Protocol, Executor>& conn_;
    const endpoint_type& addr_;
    enum {starting, connecting, creating, handshaking, done} state_;
    
    do_connect(Handler&& handler, connection_base<Protocol, Executor>& conn, const endpoint_type& addr)
    : handler_(std::move(handler))
    , conn_(conn)
    , addr_(addr)
    , state_(starting) {

    }

    do_connect(const do_connect& impl) = delete;
    do_connect(do_connect&& impl) noexcept = default;

    void operator ()(boost::system::error_code error) {         
    CONTINUE:
        switch(state_) {
        case starting:
            state_ = connecting;
            goto CONTINUE;
            // break;
        case connecting:
            state_ = creating;
            conn_.socket_.async_connect(addr_, std::move(*this));
            break;
        case creating:
            if (error) {
                boost::asio::post(conn_.get_executor(), [handler = std::move(handler_), err = error] () mutable {
                    std::move(handler)(err);
                });
                return;
            }
            conn_.create_ssl(addr_, true);
            state_ = handshaking;
            goto CONTINUE;
            // break;
        case handshaking:
            if (error) {
                boost::asio::post(conn_.get_executor(), [handler = std::move(handler_), err = error] () mutable {
                    std::move(handler)(err);
                });
                return;
            }
            BOOST_ASSERT(conn_.socket_.is_open());
            if (int r = SSL_connect(conn_.ssl_); r != 1) {
                conn_.handle_error(r, std::move(*this));
            } else {
                boost::asio::post(conn_.get_executor(), [handler = std::move(handler_), err = error] () mutable {
                    std::move(handler)(err);
                });
            }
            
        }
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CONNECT_H
