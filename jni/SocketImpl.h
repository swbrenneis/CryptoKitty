#ifndef SOCKETIMPL_H_INCLUDED
#define SOCKETIMPL_H_INCLUDED

#include <jni/JNIReference.h>
#include <string>

class SocketImpl : public CK::JNIReference {

    public:
        SocketImpl();
        SocketImpl(int fd);
        ~SocketImpl();

    private:
        SocketImpl(const SocketImpl& other);
        SocketImpl& operator= (const SocketImpl& other);

    public :
        struct Accepted {
            std::string address;
            int fd;
        };

    public:
        Accepted accept();
        void bind(const std::string hostname, short port);
        void connect(const std::string hostname, short port, int timeout);
        void close();
        void createTCPSocket();
        void createUDPSocket();
        const std::string& getHostname() const { return hostname; }
        int getSocket() const { return fd; }
        bool isConnected() const { return connected; }
        void listen(int backlog);
        void setHostname(const std::string host) { hostname = host; }
        void setSocketOption(int option, int value);

    private:
        int fd;
        std::string hostname;
        short port;
        int timeout;
        bool connected;

};

#endif // SOCKETIMPL_H_INCLUDED

