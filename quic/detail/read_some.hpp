#ifndef QUIC_DETAIL_READ_SOME_H
#define QUIC_DETAIL_READ_SOME_H

#include "connection_base.hpp"
#include "stream_base.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor, class MutableBufferSequence>
struct read_some_impl {
    using connection_type = connection_base<Protocol, Executor>;
    using stream_type = stream_base<Protocol, Executor>;
    using mutable_buffers_type = typename std::decay<MutableBufferSequence>::type;

    connection_type& conn_;
    stream_type& stream_;
    mutable_buffers_type& buffers_;

    enum {starting, connecting, configuring, handshaking, done} state_;
    template <typename Self>
    void operator()(Self& self, boost::system::error_code error = {}) {
       
    }
};


} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_READ_SOME_H
