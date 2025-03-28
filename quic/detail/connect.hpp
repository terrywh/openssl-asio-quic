#ifndef QUIC_DETAIL_CONNECT_H
#define QUIC_DETAIL_CONNECT_H

#include "connection_base.hpp"
#include "../basic_endpoint.hpp"
#include "../alpn.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor>
struct connect_impl {
    connection_base<Protocol, Executor>& conn_;
    const basic_endpoint<Protocol>&  addr_;
    const std::string& host_;
    application_protocol_list& alpn_;

    enum {starting, connecting, creating, handshaking, done} state_;
    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
CONTINUE:
        switch(state_) {
        case starting:
            state_ = connecting;
            conn_.socket_.async_connect(addr_, std::move(self));
            break;
        case connecting:
            if (error) {
                self.complete(error);
                return;
            }
            state_ = creating;
            conn_.create_ssl(addr_, host_,  alpn_, true);
            state_ = handshaking;
            goto CONTINUE;
            // break;
        case handshaking:
            if (error) {
                self.complete(error);
                return;
            }
            if (int r = SSL_connect(conn_.ssl_); r <= 0) {
                int err = SSL_get_error(conn_.ssl_, r);
                conn_.handle_ssl_error(err, std::move(self));
            } else {
                self.complete(error);
            }
        }
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_CONNECT_H
