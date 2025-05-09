#ifndef QUIC_ENDPOINT_RESOLVE_RESULT_H
#define QUIC_ENDPOINT_RESOLVE_RESULT_H

#include "endpoint.hpp"

namespace quic {

class endpoint_resolve_result {
    friend endpoint_resolve_result resolve(const std::string& host, const std::string& svc);

    std::shared_ptr<BIO_ADDRINFO> addr_;

    explicit endpoint_resolve_result(BIO_ADDRINFO* addr)
    : addr_(addr, BIO_ADDRINFO_free) {}

public:
    using value_type    = endpoint;
    class iterator {
        friend class endpoint_resolve_result;

        const BIO_ADDRINFO* i_;

        constexpr iterator(const BIO_ADDRINFO* i)
        :i_(i) {}

    public:
        using difference_type = std::ptrdiff_t;
        using value_type = endpoint;
        using reference = endpoint&;
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
            return endpoint{BIO_ADDR_dup(BIO_ADDRINFO_address(i_))};
        }
    };

    endpoint_resolve_result(const endpoint_resolve_result& es) = default;
    endpoint_resolve_result(endpoint_resolve_result&& es) = default;

    iterator begin() const {
        return iterator{addr_.get()};
    }

    iterator end() const {
        return iterator{nullptr};
    }
}; // endpoint_resolve_result

} // namespace quic

#endif // QUIC_ENDPOINT_RESOLVE_RESULT_H
