# QUIC Project Documentation

## Important points about QUIC Protocol
* QUIC - Quick UDP Internet Connections

* Encrypted by default transport protocol

* Goal is to replace tcp and tls on the web

* Provides securoty features like authentication, and encryption in the transport layer unlike with tcp where these have to be handled by the upper layers.

* The initial quic handshake contains the typical three-way handshake of tcp with the tls 1.3 handshake which provides authentication of the end-points as well as negotiation of cryptographic parameters.
    - Handshake for http over tcp + tls:
        * tcp syn
        * tcp syn + ack
        * tcp ack
        * tls client hello
        * tls server hello
        * tls finished
        * http req
        * http resp

    - Handshake for http over quic:
        * quic from client
        * quic from server
        * quic from client
        * http req
        * http resp

* QUIC also encryptes additional connection metadata that can be abused by the middleboxes to interfere with the connection. For example, QUIC encryptes even the packet numbers.

* Head of the line blocking
    - HTTP/1.1 intriduced a pipelining which allowed clients to send several http requests over the same tcp connection. However responses are still required to arrive in order so it did not really solve the HOL issue.
    - HTTP/2 solves the HOL issue by means of multiplexing requests over the same TCP connection, so a client can make multiple requests to a server without having to wait for the previous ones to complete as the responses can arrive in any order.
    - HTTP/2 has the ability to multiplex different http requests onto the same tcp connection which allows application to process requests concurently.
    - This has a downside, since multiple requests/responses are transmitted over the same tcp connection, they are all equally affected by the packet loss, even if the data loss was for one single request. This is called head of the line blocking.
    - QUIC goes a bit deeper and provides first class support for multiplexing such that different HTTP streams can in turn be mapped to different QUIC transport streams, but, while they still share the same QUIC connection so no additional handshakes are required and congestion state is shared, QUIC streams are delivered independently, such that in most cases packet loss affecting one stream doesn't affect others.

* QUIC is designed to be delivered on top of UDP datagrams, to ease deployment and avoid problems coming from network appliances that drop packets from unknown protocols, since most appliances already support UDP.

* This also allows QUIC implementations to live in user-space, so that, for example, browsers will be able to implement new protocol features and ship them to their users without having to wait for operating systems updates.

## Benchmarking various QUIC Implementations

### Quicly implementation
* qperf is a performance measurement tool for QUIC similar to iperf and uses Quicly implementation.
* [qperf-github](https://github.com/rbruenig/qperf)

#### Setting up qperf
* Select xlsmall-kernel profile on cloudlab and start an experiment with 2 nodes, client and a server.
* Login to any one node and checkout the qperf code and run the following commands. Install missing packages, if any.
* cmake is used for building qperf
* libev-dev is the library that provides event loop.
* [quicly-github](https://github.com/h2o/quicly.git) is the submodule for qperf which is a QUIC implementation being used by qperf.

```
sudo apt-get update
sudo apt-get install libev-dev
sudo apt-get install cmake
cd /proj/quic-server-PG0/users/sravi/qperf/
git submodule init
git submodule update --init -f --recursive
mkdir build
cd build
cmake ../
make
```

* Setting up TLS certificates for running qperf:
```
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 365 -nodes -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"
```

* To run qperf:
```
$ ./qperf -s
starting server with pid 2116, port 18080, cc reno, iw 10
got new connection
request received, sending data
connection 0 second 0 send window: 200406 packets sent: 311819 packets lost: 602
connection 0 second 1 send window: 257105 packets sent: 314046 packets lost: 423
connection 0 second 2 send window: 331477 packets sent: 295788 packets lost: 389
connection 0 second 3 send window: 155121 packets sent: 305621 packets lost: 426
connection 0 second 4 send window: 714845 packets sent: 330577 packets lost: 65
connection 0 second 5 send window: 243646 packets sent: 320408 packets lost: 414
connection 0 second 6 send window: 226280 packets sent: 318633 packets lost: 404
connection 0 second 7 send window: 302923 packets sent: 314323 packets lost: 360
connection 0 second 8 send window: 191804 packets sent: 303547 packets lost: 346
connection 0 second 9 send window: 212345 packets sent: 314637 packets lost: 386
transport close:code=0x0;frame=0;reason=
connection 0 second 10 send window: 213625 packets sent: 167 packets lost: 0
connection 0 total packets sent: 3129566 total packets lost: 3815
connection closed

$ ./qperf -c hp064.utah.cloudlab.us
starting client with host hp064.utah.cloudlab.us, port 18080, runtime 10s, cc reno, iw 10
connection establishment time: 15ms
time to first byte: 15ms
second 0: 2.148 gbit/s (288259434 bytes received)
second 1: 1.743 gbit/s (233941821 bytes received)
second 2: 2.339 gbit/s (313929173 bytes received)
second 3: 2.548 gbit/s (341979105 bytes received)
second 4: 2.576 gbit/s (345678348 bytes received)
second 5: 2.281 gbit/s (306139332 bytes received)
second 6: 2.216 gbit/s (297466150 bytes received)
second 7: 2.271 gbit/s (304803295 bytes received)
second 8: 2.267 gbit/s (304269064 bytes received)
second 9: 2.411 gbit/s (323548867 bytes received)
connection closed
```

#### qperf code browsing
* Setup cscope, tmux, and vim if required. Sample config files can be found in the annexure:
```
$ sudo apt-get install cscope
$ sudo apt-get install tmux
$ vim ~/.tmux.conf
$ vim ~/.vimrc
```

* Codeflow of the qperf server
    - tso: tcp segmentation offloading
    - If tso is enabled on the transmission path, the NIC divides larger data chunks into TCP segments.
    - If tso is disabled, the CPU performs segmentation for TCP/IP.
    - Hence, tso / lro improves the performance of the hosts by reducing cpu overhead for tcp/ip network operations.
    - For tcp, it is implemented on hardware. 
    - For udp, it is implemented in the kernel. This reduces the number of system calls that the application makes by sending larger chunks to kernel for segmentation instead of sending MTU sized chunks of data multiple times.
    - ```enable_gso()``` hence depends on the version of the kernel.
    - Servers are either event driven or thread based. Mostly everyone used event based servers.
    - ```ev``` and ```libevent``` are the two event based libraries.
    - SO_REUSEADDR is used for setting up the server socket so that multiple sockets can be listening on the same port. Now we can have one socket per core and all the sockets are listening on the same port and have more scalability.
    - Since this is udp, all of the accept, receive, etc are done in the application layer unlike tcp where all these are done in the socket layer.
    - qperf server, on receiving a request will do ```send_pending()``` on all the connections with the client.
    - iovec is the api that is used by ```send_pending()```. Buffer / memory to be sent is wrapper with a iovec before actually sending the data.
    - We can pass an array of iovecs' to ```send_message()```. This is done to reduce the number of system calls by accumulating and sending more data at once.
    - ```send_pending()``` is called per connection.
    - Once the iovecs' are ready, before actually sending the data QUIC protocol headers have to be added. This is handled by the api ```quicly_send()```.
    - Once ```quicly_send()``` generates the quic packets, we use ```send_dgrams()``` to send these out.
    - Implementation of ```send_dgrams()``` depends on whether gso is enabled or not.
    - ```send_dgrams_gso()``` creates one iovec for all the dgrams and sends the entire iovec at once.
    - ```send_dgrams_default()``` will look at individual dgrams, creates iovec for individual dgram, and sends it out one by one

```
main()
run_server()
    enable_gso()
    udp_listen()
    ev_io_init(&socket_watcher, &server_read_cb, server_socket, EV_READ)
    ev_io_start(loop, &socket_watcher)
    ev_init(&server_timeout, &server_timeout_cb)
    ev_run(loop)

server_read_cb(EV_P_ ev_io *w, int revents)
    recvfrom()
    quicly_decode_packet()
    server_handle_packet()
        find_conn()
        quicly_accept() / quicly_receive()
    server_send_pending()
        send_pending()
            quicly_send()
            send_dgrams()
                send_dgrams_gso() / send_dgrams_default()
```
* Codeflow of the qperf client:
    - Similar to the server
```
main()
    run_client()
        enable_gso()
        resolve_address()
        socket()
        bind()
        quicly_connect() to initiate a new conn
        enqueue_request() to add this conn to list of conns
        send_pending()
            quicly_send() to create udp packets
            send_dgrams() to send the pkts out on the wire
        ev_io_init(socket_watcher) to initialize a read watcher
        ev_io_start(loop, &socket_watcher) to start the read watcher
        ev_run(loop) to run the watcher on a loop

client_read_cb()
    recvfrom()
    quicly_decode_packet()
    quicly_receive()
    quicly_connection_is_ready()
    send_pending()
```

* Codeflow of ngtcp2 client:
```
main()
    tls_ctx.init() to initialize the tls context
    run(c, addr, port, tls_ctx)
        create_sock(remote_addr, addr, port)
        bind_addr()
        c.init() to initialize the client object
            ev_io_init(&ep.rev, readcb, fd, EV_READ) to initialize the read callback
            ngtcp2_conn_client_new() to create a new conn
            tls_session_.init() to initialize the tls session for this conn
            ev_io_start(loop_, &ep.rev) to start the read watcher
        c.on_write()
        ev_run(EV_DEFAULT, 0)

readcb():
    c->on_read(*ep)
        recvmsg(ep.fd, &msg, 0)
        ngtcp2_conn_read_pkt
    c->on_write()
        send_blocked_packet()
        write_streams() to create response pkt and send it to server
```

### ngtcp2 implementation
* [ngtcp2-github](https://github.com/ngtcp2/ngtcp2)
* 

#### ngtcp2 setup
* Using the same kernel profile that was earlier used for qperf while configuring the experiment on cloudlab.

    ```
    $ sudo apt-get update
    $ sudo apt-get install libev-dev
    $ sudo apt-get install cmake
    $ git clone --depth 1 -b OpenSSL_1_1_1q+quic https://github.com/quictls/openssl
    $ cd openssl
    $ # For Linux
    $ ./config enable-tls1_3 --prefix=$PWD/build
    $ make -j$(nproc)
    $ make install_sw
    $ cd ..
    $ git clone https://github.com/ngtcp2/nghttp3
    $ cd nghttp3
    $ autoreconf -i
    $ ./configure --prefix=$PWD/build --enable-lib-only
    $ make -j$(nproc) check
    $ make install
    $ cd ..
    $ git clone https://github.com/ngtcp2/ngtcp2
    $ cd ngtcp2
    $ autoreconf -i
    $ ./configure PKG_CONFIG_PATH=$PWD/../openssl/build/lib/pkgconfig:$PWD/../nghttp3/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,$PWD/../openssl/build/lib"
    $ make -j$(nproc) check
    ```

* Starting the server
    - Reusing the same server cert and keys that were used for qperf.
    ```
    $ ./examples/server 128.110.218.216 10080 ../qperf/build/server.key ../qperf/build/server.crt
    ```

* Starting the client
    ```
    $ ./examples/client 128.110.218.216 10080
    ```

* Starting the qperfserver:
    ```
    ./qperfserver
    ```

#### ngtcp2 code browsing
* server.cc
```
main()
    tls_ctx.init()
    Server.init()
        add_endpoint()
            create_sock()
            ev_io_init(&ep.rev, sreadcb, 0, EV_READ)
        ev_io_start()
    ev_run(EV_DEFAULT)

/* On recieving request */
server->on_read(ep)
    recvmsg() /* gets the data from the socket */
    ngtcp2_pkt_decode_version_cid() /* decode quic version from quic headers */
    handlers_.find(dcid_key)
    /* If no existing handler for the dcid of this pkt */
    ngtcp2_accept() /* Finds the */
        ngtcp2_pkt_decode_hd_long() /* Decoding headers */
    make_unique<Handler>(loop_, this) /* Creates a new handler structure */
    handler->init()
    handler->on_read()
        feed_data()
            ngtcp2_conn_read_pkt()
                conn_read_handshake() /* Performs QUIC cryptographic handshake by reading data */
                    conn_recv_handshake_cpkt() /* Can have multiple pkts */
                        conn_recv_handshake_pkt() /* Processes only one packet */
                conn_prepare_key_update() /* Post CS nhandshake */
                conn_recv_cpkt() /* processes compound pkt after handshake */
                    conn_recv_pkt() /* processes individual packets */
    handler->on_write() /* Sending data to client */
        write_streams()
            ngtcp2_conn_writev_stream()
                conn_write_vmsg_wrapper()
                    ngtcp2_conn_write_vmsg()
    
    /* Else, if handler already exists */
    handler->on_read()
    handler->on_write()
        ngtcp2_conn_get_max_udp_payload_size(conn_)
        ngtcp2_conn_get_path_max_udp_payload_size(conn_);
        ngtcp2_conn_get_send_quantum(conn_)
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_path_storage_zero(&prev_ps);
        ngtcp2_conn_get_max_data_left(conn_)
        ngtcp2_conn_writev_stream()

    handler->signal_write() /* Will start the write event */

class Handler : public HandlerBase {
    tx_;
}
```

* When server receives any packet, read event will be triggered which will give a callback to Server:on_read() function. From this callback, ngtcp2_conn_read_pkt_versioned() is invoked. If this packet belonged to any stream (i.e the data packet), ngtcp2 will give a callback to recv_stream_data() after decoding the packet and extracting the payload of the packet.

* Steps involved in writing back response on the ngtcp2 server:
    - It uses write events to send the response back to the client.
    - Whenever the server wants to start sending the response, it activates the write watcher using start_wev_endpoint().
    - When the server wants to stop sending the response, it deactivates the watcher using ev_io_stop(loop_, &wev_).
    - Once the connection is established and the server starts getting the stream packets from the client, h->signal_write() is invoked in the server read callback after some processing and reading the packet. This would start the write watcher.
    - In write_streams(), in all the error cases the watcher is activated again and returned back.

* ngtcp2's decoding procedure:
```
h->feed_data()
    ngtcp2_conn_read_pkt()
        conn_recv_cpkt()
            conn_recv_pkt()
                decrypt_pkt()
```

#### ngtcp2 performance measurement with openssl backend
* Setup the client and server:
```
/* Installing basic packages */
$ sudo apt-get update
$ sudo apt-get install libev-dev
$ sudo apt-get install cmake

/* Installing these dev tools */
$ sudo apt-get install cscope
$ sudo apt-get install tmux
$ vim ~/.tmux.conf
$ vim ~/.vimrc

/* Installing project dependencies */
$ sudo apt-get install \
    g++ \
    cmake \
    libboost-all-dev \
    libevent-dev \
    libdouble-conversion-dev \
    libgoogle-glog-dev \
    libgflags-dev \
    libiberty-dev \
    liblz4-dev \
    liblzma-dev \
    libsnappy-dev \
    make \
    zlib1g-dev \
    binutils-dev \
    libjemalloc-dev \
    libssl-dev \
    pkg-config \
    libsodium-dev

/* Installing gcc 11 */
$ sudo apt install build-essential manpages-dev software-properties-common
$ sudo add-apt-repository ppa:ubuntu-toolchain-r/test
$ sudo apt update && sudo apt install gcc-11 g++-11

/* Switching to gcc 11 */
$ sudo update-alternatives --remove-all cpp

$ sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70 --slave /usr/bin/g++ g++ /usr/bin/g++-7 --slave /usr/bin/gcov gcov /usr/bin/gcov-7 --slave /usr/bin/gcc-ar gcc-ar /usr/bin/gcc-ar-7 --slave /usr/bin/gcc-ranlib gcc-ranlib /usr/bin/gcc-ranlib-7  --slave /usr/bin/cpp cpp /usr/bin/cpp-7

$ sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 --slave /usr/bin/g++ g++ /usr/bin/g++-11 --slave /usr/bin/gcov gcov /usr/bin/gcov-11 --slave /usr/bin/gcc-ar gcc-ar /usr/bin/gcc-ar-11 --slave /usr/bin/gcc-ranlib gcc-ranlib /usr/bin/gcc-ranlib-11  --slave /usr/bin/cpp cpp /usr/bin/cpp-11
```

* Starting the server:
```
sravi@node-1:/proj/quic-server-PG0/users/sravi/ngtcp2/examples$ ./server -q 128.110.218.234 18080 server.key server.crt 
Using document root /proj/quic-server-PG0/users/sravi/ngtcp2/examples/
```

* Starting the client:
    * Just mention some http request in the end. It will not be used anywhere but will make the client send the data that we want. It is a hack for now.
```
sravi@node-0:/proj/quic-server-PG0/users/sravi/ngtcp2/examples$ ./client -q 128.110.218.234 18080 https://128.110.218.234:18080/
second 0: 1.046 gbit/s (140393429 bytes received)
second 1: 1.158 gbit/s (155359117 bytes received)
second 2: 1.114 gbit/s (149507605 bytes received)
second 3: 1.213 gbit/s (162819759 bytes received)
second 4: 1.067 gbit/s (143222049 bytes received)
second 5: 1.127 gbit/s (151236329 bytes received)
second 6: 987.6 mbit/s (129443438 bytes received)
second 7: 1.097 gbit/s (147269455 bytes received)
second 8: 1.08 gbit/s (144934096 bytes received)
second 9: 1.129 gbit/s (151512391 bytes received)
second 10: 1.063 gbit/s (142693809 bytes received)
```

#### ngtcp2 performance measurement with picotls backend
* Setup the client and server:
```
/* Installing basic packages */
$ sudo apt-get update
$ sudo apt-get install libev-dev
$ sudo apt-get install cmake

/* Installing these dev tools */
$ sudo apt-get install cscope
$ sudo apt-get install tmux
$ vim ~/.tmux.conf
$ vim ~/.vimrc

/* Installing project dependencies */
$ sudo apt-get install \
    g++ \
    cmake \
    libboost-all-dev \
    libevent-dev \
    libdouble-conversion-dev \
    libgoogle-glog-dev \
    libgflags-dev \
    libiberty-dev \
    liblz4-dev \
    liblzma-dev \
    libsnappy-dev \
    make \
    zlib1g-dev \
    binutils-dev \
    libjemalloc-dev \
    libssl-dev \
    pkg-config \
    libsodium-dev

/* Installing gcc 11 */
$ sudo apt install build-essential manpages-dev software-properties-common
$ sudo add-apt-repository ppa:ubuntu-toolchain-r/test
$ sudo apt update && sudo apt install gcc-11 g++-11

/* Switching to gcc 11 */
$ sudo update-alternatives --remove-all cpp

$ sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70 --slave /usr/bin/g++ g++ /usr/bin/g++-7 --slave /usr/bin/gcov gcov /usr/bin/gcov-7 --slave /usr/bin/gcc-ar gcc-ar /usr/bin/gcc-ar-7 --slave /usr/bin/gcc-ranlib gcc-ranlib /usr/bin/gcc-ranlib-7  --slave /usr/bin/cpp cpp /usr/bin/cpp-7

$ sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 --slave /usr/bin/g++ g++ /usr/bin/g++-11 --slave /usr/bin/gcov gcov /usr/bin/gcov-11 --slave /usr/bin/gcc-ar gcc-ar /usr/bin/gcc-ar-11 --slave /usr/bin/gcc-ranlib gcc-ranlib /usr/bin/gcc-ranlib-11  --slave /usr/bin/cpp cpp /usr/bin/cpp-11

/* Build picotls */
sravi@node-1:/proj/quic-server-PG0/users/sravi/ngtcp2$ sh ci/build_picotls.sh

/* Building ngtcp2 on picotls */
sravi@node-1:/proj/quic-server-PG0/users/sravi/ngtcp2$ autoreconf -i

sravi@node-1:/proj/quic-server-PG0/users/sravi/ngtcp2$ ./configure --with-picotls PICOTLS_CFLAGS="-I$PWD/picotls/include/" PICOTLS_LIBS="-L$PWD/picotls/build -lpicotls-openssl -lpicotls-core" PKG_CONFIG_PATH=$PWD/../nghttp3/build/lib/pkgconfig

sravi@node-1:/proj/quic-server-PG0/users/sravi/ngtcp2$ make -j$(nproc) check
```

* Starting the server:
```
sravi@node-1:/proj/quic-server-PG0/users/sravi/ngtcp2/examples$ ./ptlsserver -q 128.110.218.234 18080 server.key server.crt 
Using document root /proj/quic-server-PG0/users/sravi/ngtcp2/examples/
```

* Starting the client:
```
sravi@node-0:/proj/quic-server-PG0/users/sravi/ngtcp2/examples$ ./ptlsclient -q 128.110.218.234 18080 https://128.110.218.234:18080/
second 0: 1.093 gbit/s (146766989 bytes received)
second 1: 1.167 gbit/s (156639762 bytes received)
second 2: 1.184 gbit/s (158887444 bytes received)
second 3: 1.18 gbit/s (158356637 bytes received)
second 4: 1.195 gbit/s (160420791 bytes received)
second 5: 1.177 gbit/s (157980849 bytes received)
second 6: 1.156 gbit/s (155180375 bytes received)
second 7: 1.158 gbit/s (155477305 bytes received)
second 8: 1.168 gbit/s (156807862 bytes received)
second 9: 1.178 gbit/s (158142024 bytes received)
second 10: 1.19 gbit/s (159657850 bytes received)
```

* By default, no_gso = False on xl-small kernel and hence gso is enabled.
* Datasize of each packet in write_streams() when streaming data is max_udp_payload_size. For this size, gso is not used as it will fit in one MTU.
* CPU usage of the server is around 75% whereas when running qperf, the cpu usage of the server was around 95%.
* Now, disabling gso manually and increasing the datasize to 16*max_udp_payload_size below is the throughput seen on the client:
```
sravi@node-0:/proj/quic-server-PG0/users/sravi/ngtcp2/examples$ ./ptlsclient -q 128.110.218.237 10080 https://128.110.218.237:10080/
second 0: 1.109 gbit/s (148800611 bytes received)
second 1: 1.26 gbit/s (169081517 bytes received)
second 2: 1.211 gbit/s (162479838 bytes received)
second 3: 1.273 gbit/s (170900439 bytes received)
second 4: 1.211 gbit/s (162583717 bytes received)
second 5: 1.27 gbit/s (170436870 bytes received)
second 6: 1.26 gbit/s (169141391 bytes received)
second 7: 1.258 gbit/s (168902916 bytes received)
second 8: 1.239 gbit/s (166301437 bytes received)
second 9: 1.184 gbit/s (158949195 bytes received)
second 10: 1.173 gbit/s (157443235 bytes received)
```

* As seen above, throughput increased slightly and the cpu usage of the server went up to around 90%.

#### Profiling ngtcp2:
* Setting up the tools required for cpu profiling:
```
/* Install linux perf tool using the command below. Kernel specific packages might be required, just follow the error message. */
$ sudo apt install linux-tools-common
$ sudo apt install linux-cloud-tools-generic

/* Install flame graphs to visualize the stats */
$ git clone https://github.com/brendangregg/FlameGraph
```

* Steps to generate the flame graphs:
```
/* Start the ngtcp2 server */
sravi@node-1:/proj/quic-server-PG0/users/sravi/qperf$ ./server -q 128.110.218.234 18080 server.key server.crt

/* Start the perf record on server */
$ sudo perf record -F 99 -p <server_pid> -g -- sleep <duration of record>

$ sudo perf script | ./stackcollapse-perf.pl > out.perf-folded

/* Generate the flame graph for visualization */
FlameGraph$ ./flamegraph.pl out.perf-folded > ngtcp2_server_perf.svg

/* Open the ngtcp2_server_perf.svg on any browser for visualising the cpu stats */
```

#### Observations from flame graph of ngtcp2 with picotls
* In this case, datasize of each pkt was max_udp_payload_size.
* SSL related tasks: 25.79%
* ev_invoke_pending(): 27.26%
    - Mostly doing libc_recvmsg
* epoll_wait(): 5.43%
* malloc(): 11.7%
* Unknown: 27.96%
    - libc_sendmsg: 7.75%
    - conn_recv_pkt: 0.67%
    - conn_write_pkt: 0.4%
    - debug_pkt_lost: 0.76%
    - decode_stream_frame: 0.4%
    - encode_stream_frame: 0.4%
    - feed_data: 0.4%
    - on_write: 0.83%
    - write_streams: 0.11%
    - encode_ack_frame: 0.3%

* Highlights:
    - malloc is consuming significant amount of cpu
    - epoll_wait is consuming more cpu compared to qperf
    - ev_invoke_pending is consuming significantly less cpu
        * One reason is libc_sendmsg call is itself taking 63% and is included in this in the case of qperf.
    - SSL related tasks are very similar

#### Observations from flame graph of quicly
* SSL related tasks: 24.55%
* ev_invoke_pending(): 66.11%
* epoll_wait(): 0.73%
* malloc(): 0.15%
* sending streams: 1.28%
* Unknown: 7.11%


- ngtcp2 code browsing and debugging on gdb
    - ngtcp2_accept was invoked with pktlen = udp payload = 1200 bytes
    - ngtcp2_pkt_decode_hd_long() returned 47 which is quic header length
- Reverted back to old code and fixed compilation errors
- Included qperf for other versions of ssl libraries
- Added code until ngtcp2_accept, conn find and add apis, calling creating new conn api

- Where is h->conn() implemented?
- Where exactly is ACK sent by the server during handshake?
- dcid (destination connection id can be used as an unique identifier of the connection). How exactly to use this as the identifier?
- Where is conn_ declared? Is it the one in HandlerBase class in server_base.h?

##### 09/19:
1. What is the difference between tls session and tls context in ngtcp2? <br>
tls context is an equivalent of SSL_CTX for the appropriate ssl implementation that is being used. It holds various configuration and data relevant to ssl session establishment.

##### Steps involved in ssl encryption:
1. SSL handshake
    * Asymetric cryptography
    * Client hello
    * Server hello
    * Client creates and sends an encrypted session key
    * Server sends ack

2. Actual data transfer
    * Using the session key that client created, client will now encrypt data with that key and send it to server.
    * Server already knows the key, so it will decrypt the message, form a response, encrypt it with the same key and send it back to the client.

ssl context (SSL_ctx): <br>
A context structure is needed for each app that is running ssl. This is standard ssl library.

tls context in ngtcp2 example:
1. TLSServerContext &tls_ctx. This is the class name.
2. It contains the following:
    * Constructor: TLSServerContext()
    * Destructor: ~TLSServerContext()
    * init(private_key_file, cert_file, proto):
        - This is invoked once in main() of server.cc
        - First creates SSL_CTX_new
        - Then configures tls version and quic method for ssl_ctx by calling ngtcp2_crypto_openssl_configure_server_context()
        - Sets cipher suites for ssl_ctx
        - Few other configs for ssl_ctx
        - Sets the private key file to the ssl_ctx
        - Sets the crt file to the ssl_ctx

    * get_native_handle()
        - Just returns ssl_ctx associated with the tls_ctx object.
        - This is called during TLSServerSession init().

    * enable_keylog()
        - Sets SSL_CTX_set_keylog_callback() for ssl_ctx

tls session in ngtcp2 example:
1. TLSServerSession tls_session_. This is the class name.
2. It contains the following:
    * Constructor: TLSServerSession()
    * Destructor: ~TLSServerSession()
    * init(tls_ctx, handler)
        - Is invoked during handler init(). Handler is an object that is created for every QUIC conn which is a wrapper that handles everything for the server for a conn.
        - Gets ssl_ctx by calling get_native_handle()
        - Creates a new ssl structure by invoking SSL_new() to hold the data for one ssl connection.
        - Sets the ngtcp2_crypto_conn_ref of this conn to this ssl structure
        - Sets the ssl struct to accept state
        - Enables QUIC early data on this ssl struct

    * send_session_ticket()
        - Returns 0 always.
        - Is invoked when ngtcp2 gives a callback once a handshake is completed.

handler has the following:
1. ngtcp2_conn *conn_
2. TLSServerSession tls_session_
3. ngtcp2_crypto_conn_ref conn_ref_
    * It is a structure to get a pointer to ngtcp2_conn
    * It is meant to be set to TLS native handler as an application specific data (SSL_set_app_data)
    * 


```
main()
    tls_ctx.init(key file, cert file, protocol)
    Server s(EV_DEFAULT, tls_ctx)

server->on_read()
    h->init(tls_ctx)
        tls_session_.init(tls_ctx, this)
```

tls session: <br>
Each handler is linked to a tls server session object that uses tls context. It contains the following:
1. init()
2. send_session_ticket()
```
handler->init()
    tls_session_.init(tls_ctx, this)

class HandlerBase {
    TLSServerSession tls_session_;
}
```

2. Should we use one tls context for all the connections or use one tls context per connection?
3. Next step is to link a tls context to a connection and decode the quic packet.
4. Then form a response out of the same payload and send the response back to the client.

conn_read_handshake() is failing because conn_recv_handshake_cpkt() is failing because conn_recv_handshake_pkt() is failing because conn_recv_crypto() is failing because conn_call_recv_crypto_data() is failing because ngtcp2_crypto_recv_crypto_data_cb() is failing because SSL_do_handshake() is failing because ngtcp2_conn_set_remote_transport_params() is failing because ngtcp2_cid_eq() is failing.

recv_crypto_data() is failing which is a callback function that gets invoked when the cryptographic data is received.

Need to do everything that is done in TLSServerSession::init():
1. Create new ssl structure using SSL_new()
2. SSL_set_app_data() so that this ssl struct is mapped to conn_ref. This is needed because later on ssl libraries needs to fetch conn_ref from ssl struct (see SSL_get_app_data) to in turn get the conn pointer that will be used in callbacks (using conn_ref->conn).
3. Set the ssl to accept state and enable quic early data.

conn_ref <-> ssl (SSL_get_app_data, SSL_set_app_data)
conn_ref <-> conn (get_conn())

ngtcp2_crypto_conn_ref:
    get_conn (user has to implement, will be used by ssl libraries like set_encryption_secrets)
    user_data (user can use it to store any data, we need to somehow use this to get conn pointer from conn_ref)

abstractions in ngtcp2:
1. ssl
2. conn
3. conn_ref

conn <- conn_ref <-> ssl


event loop data structures:
1. ev_timer
2. EV_P: struct ev_loop *loop
3. struct ev_io
4. How to initialize an io on the server:
    ```
    struct ev_loop *loop = EV_DEFAULT;
    ev_io socket_watcher;
    ev_io_init(&socket_watcher, &server_read_cb, server_socket, EV_READ);
    ev_io_start(loop, &socket_watcher);
    ev_init(&server_timeout, &server_timeout_cb);
    ev_run(loop, 0);
    ```

## Meeting notes:
* Most of the performance difference is due to:
    - Memory allocation
    - Having a separate event for writing response on the server. Maybe this is the reason why epoll_wait is more in ngtcp2.

* Next steps:
    - Try calling write_streams directly instead of via an event loop
    - Observations after this change:
        * epoll_wait has reduced from 5.43% to 1.79%
        * libc_sendmsg() has increased from 7.75% to 33.7%
        * libc_recvmsg() has reduced from 23.59% to 14.24%
        * Overall the sum of recvmsg() and sendmsg() has increased from 31.34% to 47.94%.
        * Throughput is around 900 mbps

 * Possible reasons for this throughput reduction:
    - Missing any write event that was there earlier. Handled this and the throughput increased slightly.

    - The changes done are only on the server, so maybe changing the client will help.
        * on_write() is invoked by writecb, readcb, and one time once the client starts and is ready.
        * writecb is invoked when write_streams reaches max pkt count.
        * readcb is invoked when client receives any pkt.
        * Hence, no changes on client needed as the main invocation is sync call instead of events like server.
        
    - The place where the event is replaced with a direct call may not be the right way. If it changes the logic of the initial code then its not the right way of invoking the call directly.
        * Yeah it alters the flow of the server. Server was earlier activating the write event and wait for reading 10 packets and only then return. Now calling directly for every packet will change this flow.
        * Remove un-necessary callbacks from the connection. Done. Because of this epoll_wait has reduced to 1.78% of the cpu.
        * In the read and write funtions, check if any optional processing can be removed.
        * Try invoking write_streams() twice in on_write() function and see if the throughput increases.

    - Throughput after the above changes has increased by 300 mbps.
    - Please refer the flame graph [here](https://github.com/ShashiKiranMR/ngtcp2/blob/dev/flame_graphs/ngtcp2_ptls_server_write_events_latest.svg).
    - All the flame graphs can be found [here](https://github.com/ShashiKiranMR/ngtcp2/tree/dev/flame_graphs).
```
sravi@node-0:/proj/quic-server-PG0/users/sravi/ngtcp2/examples./ptlsclient -q 10.10.1.2 18080 https://10.10.1.2:18080/
second 0: 1.562 gbit/s (209690068 bytes received)
second 1: 1.501 gbit/s (201398102 bytes received)
second 2: 1.422 gbit/s (190888912 bytes received)
second 3: 1.42 gbit/s (190602306 bytes received)
second 4: 1.48 gbit/s (198674887 bytes received)
second 5: 1.456 gbit/s (195476237 bytes received)
second 6: 1.438 gbit/s (192973821 bytes received)
second 7: 1.476 gbit/s (198130820 bytes received)
second 8: 1.468 gbit/s (197049326 bytes received)
second 9: 1.494 gbit/s (200521916 bytes received)
second 10: 1.452 gbit/s (194869785 bytes received)
```
    
- timeoutcb is also invoking on_write(). Understand why this is happens.
    * Initially timer is configured with 'after' and 'repeat' as 0.
    * In on_read() and on_write(), timer is updated using the connection expiry time.
    * ngtcp2_conn_get_send_quantum() returns the number of bytes that can be sent without packet spacing.
    * After one or more calls of ngtcp2_conn_writev_stream(), ngtcp2_conn_update_pkt_tx_time() has to be called. This will set the timer on when the next packet should be sent.
    * We can get this value in future by calling ngtcp2_conn_get_expiry(). This is called in update_timer() that is called on every read and write of a quic packet.

## Annexure

### tmux.conf
```
# remap prefix from 'C-b' to 'C-a'
unbind C-b
set-option -g prefix `
bind-key ` send-prefix
# split panes using | and -
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %
# switch panes using Alt-arrow without prefix
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D
# Enable mouse control (clickable windows, panes, resizable panes)
set -g mouse on
```

### vimrc
* A neat and basic version of vimrc can be found [here](https://github.com/amix/vimrc/blob/master/vimrcs/basic.vim)
* Copy the contents into ``` $HOME/.vimrc```

### cscope tags and mappings
* Official cscope config file for vim can be found [here](http://cscope.sourceforge.net/cscope_maps.vim)
* Copy the contents into ``` $HOME/.vimrc```