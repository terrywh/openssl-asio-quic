#ifndef QUIC_IMPL_STREAM_H
#define QUIC_IMPL_STREAM_H

#include "../detail/asio.hpp"
#include "connection.hpp"

namespace quic {
namespace impl {

struct stream {
    using executor_type = impl::connection::executor_type;

    SSL*           handle_;
    executor_type& strand_;

    stream(SSL* handle, impl::connection* conn)
    : handle_(handle)
    , strand_(conn->strand_) {}
};

} // namespace impl
} // namespace quic

#endif // QUIC_IMPL_STREAM_H
