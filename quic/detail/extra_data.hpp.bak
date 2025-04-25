#ifndef QUIC_DETAIL_EXTRA_DATA_H
#define QUIC_DETAIL_EXTRA_DATA_H
#include <openssl/crypto.h>

namespace quic {
namespace detail {

template <class T>
struct extra_data {
    static void free_cb (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
        int idx, long argl, void *argp) {
      
      if (!ptr) return;
      delete reinterpret_cast<T*>(ptr);
    }

    static int ext_idx() {
        static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, &free_cb);
        return idx;
    }

    static void attach(SSL* ssl, T* ptr) {
        if (ssl) SSL_set_ex_data(ssl, ext_idx(), ptr);
    }

    static T* detach(SSL* ssl) {
        void* ptr = nullptr;
        int idx = ext_idx();
        if (ssl) {
            ptr = SSL_get_ex_data(ssl, idx);
            SSL_set_ex_data(ssl, idx, nullptr);
        }
        return reinterpret_cast<T*>(ptr);
    }
};

} // namespace detail
} // namespace quic

#endif // QUIC_DETAIL_EXTRA_DATA_H