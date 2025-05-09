#ifndef QUIC_ENDPOINT_H
#define QUIC_ENDPOINT_H

#include "endpoint_basic.hpp"
#include "proto.hpp"

namespace quic {
    using endpoint = endpoint_basic<proto>;
} // namespace quic

#endif // QUIC_ENDPOINT_H
