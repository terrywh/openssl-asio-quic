#ifndef QUIC_BASIC_ENDPOING_H
#define QUIC_BASIC_ENDPOING_H

#include "detail/asio.hpp"
#include "detail/ssl.hpp"
#include <format>

namespace quic {


template <class Protocol>
class basic_endpoint {
public:
    using protocol_type = typename std::decay<Protocol>::type;
    using port_type = std::uint16_t;

private:
    BIO_ADDR* addr_;

    explicit basic_endpoint(BIO_ADDR* addr)
    : addr_(addr) {}

public:
    basic_endpoint()
    : addr_(nullptr) {}

    basic_endpoint(const basic_endpoint& e)
    : addr_(BIO_ADDR_dup(e.addr_)) {}

    basic_endpoint(basic_endpoint&& e)
    : addr_(BIO_ADDR_dup(e.addr_)) {
        
    }

    ~basic_endpoint() {
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
    friend class basic_endpoints;
};

template <class Protocol>
class basic_endpoints {
public:
    using protocol_type = typename std::decay<Protocol>::type;
    using port_type = std::uint16_t;
    using value_type = basic_endpoint<Protocol>;

private:
    std::shared_ptr<BIO_ADDRINFO> addr_;

    explicit basic_endpoints(BIO_ADDRINFO* addr)
    : addr_(addr, BIO_ADDRINFO_free) {}

public:
    class iterator {
        template <class Protocol1>
        friend class basic_endpoints;

        const BIO_ADDRINFO* i_;

        constexpr iterator(const BIO_ADDRINFO* i)
        :i_(i) {}

    public:
        using difference_type = std::ptrdiff_t;
        using value_type = basic_endpoint<Protocol>;
        using reference = basic_endpoint<Protocol>&;
        using iterator_category = std::forward_iterator_tag;

        iterator& operator ++() {
            i_ = BIO_ADDRINFO_next(i_);
            return *this;
        }

        constexpr iterator operator ++(int) const {
            return {BIO_ADDRINFO_next(i_)};
        }

        constexpr bool operator != (const iterator& it) const {
            return i_ != it.i_;
        }

        constexpr bool operator == (const iterator& it) const {
            return i_ == it.i_;
        }

        value_type operator*() const {
            return basic_endpoint<Protocol>{BIO_ADDR_dup(BIO_ADDRINFO_address(i_))};
        }
    };

    basic_endpoints(const basic_endpoints& es) = default;

    iterator begin() const {
        return iterator{addr_.get()};
    }

    iterator end() const {
        return iterator{nullptr};
    }

    template <class Protocol1>
    friend basic_endpoints<Protocol1> resolve(const std::string& host, const std::string& svc);
}; // basic_endpoints

} // namespace quic

#endif // QUIC_BASIC_ENDPOING_H
