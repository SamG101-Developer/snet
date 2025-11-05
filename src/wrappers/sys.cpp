module;

#include <cerrno>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

export module sys;


// <sys/file.h>
export namespace sys {
    using ::flock;
}

// <sys/socket.h>
export namespace sys {
    using socket_t = int;
    using ::socklen_t;
    using ::sockaddr_in;
    using ::sockaddr;
    using ::ssize_t;
    using ::addrinfo;

    using ::socket;
    using ::close;
    using ::bind;
    using ::connect;
    using ::listen;
    using ::accept;
    using ::sendto;
    using ::send;
    using ::recvfrom;
    using ::recv;
    using ::setsockopt;
    using ::socketpair;

    using ::htons;
    using ::inet_pton;
    using ::inet_ntop;
    using ::ntohs;

    using ::getaddrinfo;
    using ::freeaddrinfo;

#undef AF_INET
    constexpr auto AF_INET = PF_INET;
#undef AF_INET6
    constexpr auto AF_INET6 = PF_INET6;
#undef AF_UNIX
    constexpr auto AF_UNIX = PF_UNIX;
#undef SOCK_DGRAM
    constexpr auto SOCK_DGRAM = __socket_type::SOCK_DGRAM;
#undef SOCK_STREAM
    constexpr auto SOCK_STREAM = __socket_type::SOCK_STREAM;
#undef SOL_SOCKET
    constexpr auto SOL_SOCKET = 1;
#undef SO_REUSEADDR
    constexpr auto SO_REUSEADDR = 2;
#undef IPPROTO_UDP
    constexpr auto IPPROTO_UDP = 17;
#undef IPPROTO_TCP
    constexpr auto IPPROTO_TCP = 6;
#undef INADDR_ANY
    constexpr auto INADDR_ANY = static_cast<in_addr>(0);
#undef INET_ADDRSTRLEN
    constexpr auto INET_ADDRSTRLEN = 16;
}

// <sys/select.h>
export namespace sys {
    using ::select;
    using ::fd_set;
#undef FD_SET
    auto FD_SET = [](const int fd, fd_set *set) { __FD_SET(fd, set); };
#undef FD_CLR
    auto FD_CLR = [](const int fd, fd_set *set) { __FD_CLR(fd, set); };
#undef FD_ISSET
    auto FD_ISSET = [](const int fd, fd_set const *set) { return __FD_ISSET(fd, set); };
#undef FD_ZERO
    auto FD_ZERO = [](fd_set *set) { __FD_ZERO(set); };
}


// <sys/time.h>
export namespace sys {
    using ::timeval;
}
