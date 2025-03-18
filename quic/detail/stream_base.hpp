#ifndef QUIC_DETAIL_STREAM_BASE_H
#define QUIC_DETAIL_STREAM_BASE_H

#include "connection_base.hpp"

namespace quic {
namespace detail {

template <class Protocol, class Executor>
class stream_base {
public:
    using connection_type = connection_base<Protocol, Executor>;
protected:
    connection_type& conn_;
    SSL* ssl_;
    
public:
    stream_base(connection_base<Protocol, Executor>& conn, SSL* s)
    : conn_(conn)
    , ssl_(s) {}
};

}
}

#endif // QUIC_DETAIL_STREAM_BASE_H
