#include <openssl/ssl.h>

int main(int argc, char* argv[]) {
    int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);

    return SSL_set_ex_data(nullptr, index, new int{123});
}
