### 依赖

#### openssl

```
cd /data/stage/openssl-3.5.0-alpha1/demos/guide
LD_LIBRARY_PATH=../.. ./quic-server-block 8443 servercert.pem serverkey.pem
SSL_CERT_FILE=servercert.pem LD_LIBRARY_PATH=../.. ./quic-client-block localhost 8443
```
