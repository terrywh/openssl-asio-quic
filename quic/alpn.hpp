#ifndef ASIO_QUIC_DETAIL_ALPN_H
#define ASIO_QUIC_DETAIL_ALPN_H

#include <boost/assert.hpp>
#include <initializer_list>

namespace quic {

class application_protocol_list {
    std::size_t                size_;
    std::vector<unsigned char> list_;

public:

    class iterator {
        const unsigned char* i_;
    public:
        constexpr iterator(const unsigned char* i)
        : i_(i) {}

        constexpr iterator& operator ++() {
            i_ += i_[0];
            return *this;
        }
        constexpr iterator operator ++(int) const {
            return iterator{i_ + i_[0]};
        }
        constexpr bool operator != (const iterator& it) const {
            return it.i_ != i_;
        }
    };

    constexpr explicit application_protocol_list()
    : size_(0) {

    }

    constexpr explicit application_protocol_list(std::initializer_list<std::string> protos)
    : size_(protos.size()) {
        for (auto& proto : protos) {
            list_.push_back(static_cast<unsigned char>(proto.size()));
            list_.insert(list_.end(), proto.begin(), proto.end());
        }
    }

    application_protocol_list(const application_protocol_list& alpn) = default;

    application_protocol_list& operator =(const application_protocol_list& alpn) = default;

    constexpr operator const unsigned char*() const {
        return list_.data();
    }

    constexpr iterator begin() const {
        return {list_.data()};
    }

    constexpr iterator end() const {
        return {list_.data() + list_.size()};
    }

    constexpr std::size_t size() const {
        return list_.size();
    }
}; // class application_protocol_list

} // namespace quic

#endif // ASIO_QUIC_DETAIL_ALPN_H
