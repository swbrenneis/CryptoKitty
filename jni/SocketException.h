#ifndef SOCKETEXCEPTION_H_INCLUDED
#define SOCKETEXCEPTION_H_INCLUDED

#include <exception>
#include <string>

#ifdef __MACH__
#define EXCEPTION_THROW_SPEC throw()
#else
#define EXCEPTION_THROW_SPEC noexcept
#endif

class SocketException  : public std::exception {

    public:
        SocketException() {}
        SocketException(const std::string& msg) : message(msg) {}
        SocketException(const SocketException& other)
                : message(other.message) {}
        ~SocketException() {}

    private:
        SocketException& operator= (const SocketException& other);

    public:
        const char *what() const EXCEPTION_THROW_SPEC { return message.c_str(); }

    private:
        std::string message;

};

#endif // SOCKETEXCEPTION_H_INCLUDED
