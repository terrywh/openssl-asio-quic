#ifndef QUIC_ENDPOINT_BASIC_H
#define QUIC_ENDPOINT_BASIC_H

#include "detail/asio.hpp"
#include "detail/ssl.hpp"
#include <format>

namespace quic {

template <class Proto>
class endpoint_basic {
    friend class endpoint_resolve_result;

public:
    using protocol_type = typename std::decay<Proto>::type;
    using port_type = std::uint16_t;

private:
    BIO_ADDR* addr_;

    explicit endpoint_basic(BIO_ADDR* addr)
    : addr_(addr) {}

public:
    endpoint_basic()
    : addr_(nullptr) {}

    endpoint_basic(const boost::asio::ip::address& addr, std::uint16_t port)
    : addr_(BIO_ADDR_new()) {
        int r = 0;
        if (addr.is_v6()) {
            auto v6 = addr.to_v6();
            r = BIO_ADDR_rawmake(addr_, AF_INET6, v6.to_bytes().data(), sizeof(in6_addr), htons(port));
        } else {
            auto v4 = addr.to_v4();
            r = BIO_ADDR_rawmake(addr_, AF_INET, v4.to_bytes().data(), sizeof(in_addr), htons(port));
        }
        if (!r) throw boost::system::system_error{
            boost::asio::error::address_family_not_supported,
            boost::asio::error::get_system_category()};
    }

    endpoint_basic(const endpoint_basic& e)
    : addr_(BIO_ADDR_dup(e.addr_)) {}

    endpoint_basic(endpoint_basic&& e)
    : addr_(std::exchange(e.addr_, nullptr)) {

    }
    ~endpoint_basic() {
        if (addr_ != nullptr) BIO_ADDR_free(addr_);
    }
    protocol_type protocol() const {
        return addr_ == nullptr ? protocol_type::unspecified() :
            BIO_ADDR_family(addr_) == AF_INET6 ? protocol_type::v6() : protocol_type::v4();
    }
    const void* data() const {
        return static_cast<const void*>(addr_);
    }
    void* data() {
        return static_cast<void*>(addr_);
    }
    std::size_t size() const {
        return BIO_ADDR_family(addr_) == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    }
    void resize(std::size_t s) {
        throw std::runtime_error("not supported");
    }
    std::size_t capacity() const {
        return sizeof(struct sockaddr);
    }
    constexpr operator const BIO_ADDR* () const {
        return addr_;
    }
    std::string to_string() const {
        char* host = BIO_ADDR_hostname_string(addr_, 1);
        char* port = BIO_ADDR_service_string(addr_, 1);

        std::string s = std::format("{}:{}", host, port);

        OPENSSL_free(host);
        OPENSSL_free(port);
        return s;
    }

    template <class Protocol1>
    friend class endpoints;
};

} // namespace quic

#endif // QUIC_ENDPOINT_BASIC_H
