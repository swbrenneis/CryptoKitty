/**
 * 
 */
package org.cryptokitty.jni;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketImpl;

/**
 * @author stevebrenneis
 *
 */
public class BerkeleySocketImpl extends SocketImpl {

	/**
	 * Load the CryptoKitty-C binary.
	 */
	static {
		System.loadLibrary("ckjni");
	}

	/**
	 * The opaque JNI reference.
	 */
	private long jniImpl;

	/**
	 * 
	 */
	public BerkeleySocketImpl() {

		jniImpl = initialize();

	}

	/**
	 * Initialize the JNI reference;
	 * 
	 * @return
	 */
	private native long initialize();
	
	/**
	 * Get the underlying Unix file descriptor.
	 * 
	 * @return
	 */
	public native int getNativeFileDescriptor();


	/* (non-Javadoc)
	 * @see java.net.SocketOptions#setOption(int, java.lang.Object)
	 */
	@Override
	public native void setOption(int optID, Object value) throws SocketException;
	
	/* (non-Javadoc)
	 * @see java.net.SocketOptions#getOption(int)
	 */
	@Override
	public native Object getOption(int optID) throws SocketException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#create(boolean)
	 */
	@Override
	protected native void create(boolean stream) throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#connect(java.lang.String, int)
	 */
	@Override
	protected void connect(String host, int port) throws IOException {

		nativeConnect(host, port, 0);

	}

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#connect(java.net.InetAddress, int)
	 */
	@Override
	protected void connect(InetAddress address, int port) throws IOException {

		nativeConnect(address.getHostAddress(), port, 0);

	}

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#connect(java.net.SocketAddress, int)
	 */
	@Override
	protected void connect(SocketAddress address, int timeout) throws IOException {

		InetSocketAddress inetAddress = (InetSocketAddress)address;
		String hostname = inetAddress.getHostName();
		int port = inetAddress.getPort();
		nativeConnect(hostname, port, timeout);

	}
	
	/**
	 * The native connect method.
	 * 
	 * @param address
	 * @param port
	 * @param timeout
	 * @throws IOException
	 */
	private native void nativeConnect(String address, int port, int timeout) throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#bind(java.net.InetAddress, int)
	 */
	@Override
	protected void bind(InetAddress host, int port) throws IOException {

		nativeBind(host.getHostName(), port);

	}

	/**
	 * The native bind method.
	 * 
	 * @param hostname
	 * @param port
	 */
	private native void nativeBind(String hostname, int port);

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#listen(int)
	 */
	@Override
	protected native void listen(int backlog) throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#accept(java.net.SocketImpl)
	 */
	@Override
	protected native void accept(SocketImpl s) throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#getInputStream()
	 */
	@Override
	protected native InputStream getInputStream() throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#getOutputStream()
	 */
	@Override
	protected native OutputStream getOutputStream() throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#available()
	 */
	@Override
	protected native int available() throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#close()
	 */
	@Override
	protected native void close() throws IOException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#sendUrgentData(int)
	 */
	@Override
	protected native void sendUrgentData(int data) throws IOException;
	
}
