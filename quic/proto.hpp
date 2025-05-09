#ifndef QUIC_PROTO_H
#define QUIC_PROTO_H

#include "detail/asio.hpp"
#include "endpoint_basic.hpp"

namespace quic {

// proto
// @concept Protocol
class proto {
public:
    using endpoint = endpoint_basic<proto>;

    static proto unspecified() noexcept {
        return proto(BOOST_ASIO_OS_DEF(AF_UNSPEC));
    }

    static proto v4() noexcept {
        return proto(BOOST_ASIO_OS_DEF(AF_INET));
    }

    static proto v6() noexcept {
        return proto(BOOST_ASIO_OS_DEF(AF_INET6));
    }

    int family() const {
        return family_;
    }
    int type() const {
        return BOOST_ASIO_OS_DEF(SOCK_DGRAM);
    }
    int protocol() const {
        return BOOST_ASIO_OS_DEF(IPPROTO_UDP);
    }

private:
    int family_;
    explicit proto(int family): family_(family) {}
}; // class proto



} // namespace quic

#endif // QUIC_PROTO_H
