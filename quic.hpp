#ifndef QUIC_H
#define QUIC_H

#include "quic/proto.hpp"
#include "quic/basic_server.hpp"
#include "quic/basic_connection.hpp"
#include "quic/resolve.hpp"
#include "quic/connect.hpp"

namespace quic {
    using endpoint = quic::basic_endpoint<proto>;
    using connection = quic::basic_connection<proto>;
    using stream = quic::basic_stream<proto>;
    using server = quic::basic_server<proto>;
} // namespace quic

#endif // QUIC_H
