#include "SocketImpl.h"
#include "SocketException.h"
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

SocketImpl::SocketImpl()
: connected(false) {
}

SocketImpl::SocketImpl(int socket)
: fd(socket),
  connected(false) {
}

SocketImpl::~SocketImpl() {
}

SocketImpl::Accepted SocketImpl::accept() {

    sockaddr_storage clientname;
    socklen_t size = sizeof(clientname);
    int newconn = ::accept(fd, reinterpret_cast<sockaddr*>(&clientname), &size);
    if (newconn < 0) {
        std::ostringstream str;
        str << "Socket accept error: " << strerror(errno);
        throw SocketException(str.str());
    }

    Accepted accepted;
    sockaddr_in *clientAddr = reinterpret_cast<sockaddr_in*>(&clientname);
    accepted.address = inet_ntoa(clientAddr->sin_addr);
    accepted.fd = newconn;
    return accepted;

}

void SocketImpl::close() {

    ::close(fd);
    connected = false;

}

void SocketImpl::bind(const std::string h, short p) {

    hostname = h;
    port = p;

    // Give the socket a name.
    hostent *bindaddr = gethostbyname(hostname.c_str());
    if (bindaddr->h_addr == 0) {
        std::ostringstream str;
        str << "Error in bind name resolution, " << hostname
            << " not found";
        throw SocketException(str.str());
    }

    struct sockaddr_in name;
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    memcpy(&name.sin_addr.s_addr, bindaddr->h_addr, bindaddr->h_length);
    int res = ::bind(fd, (struct sockaddr*)&name, sizeof (name));
    if (res < 0) {
        std::ostringstream str;
        str << "Socket bind error: " << strerror(errno);
        throw SocketException(str.str());
    }

}

void SocketImpl::connect(const std::string h, short p, int t) {

    hostname = h;
    port = p;
    timeout = t;

    hostent *server = gethostbyname(hostname.c_str());
    if (server->h_addr == 0) {
        std::ostringstream str;
        str << "Error in host name resolution, " << hostname
            << " not found";
        throw SocketException(str.str());
    }

    struct sockaddr_in name;
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    memcpy(&name.sin_addr.s_addr, server->h_addr, server->h_length);
    int res = ::connect(fd, reinterpret_cast<sockaddr*>(&name), sizeof (name));
    if (res < 0) {
        std::ostringstream str;
        str << "Socket connect error: " << strerror(errno);
        throw SocketException(str.str());
    }
    connected = true;

}

void SocketImpl::createTCPSocket() {

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::ostringstream str;
        str << "Socket create error: " << strerror(errno);
        throw SocketException(str.str());
    }

}

void SocketImpl::createUDPSocket() {

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::ostringstream str;
        str << "Socket create error: " << strerror(errno);
        throw SocketException(str.str());
    }

}

void SocketImpl::listen(int backlog) {

     int res = ::listen(fd, backlog);
     if (res < 0) {
        std::ostringstream str;
        str << "Socket listen error: " << strerror(errno);
        throw SocketException(str.str());
     }
     connected = true;

}

void SocketImpl::setSocketOption(int option, int value) {

    int optval = value;
    int res = setsockopt(fd, SOL_SOCKET, option, (void *) &optval, sizeof(int));
     if (res < 0) {
        std::ostringstream str;
        str << "Set socket option error: " << strerror(errno);
        throw SocketException(str.str());
     }

}

