/**
 * 
 */
package org.cryptokitty.jni;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import org.cryptokitty.exceptions.CKSocketException;

/**
 * @author stevebrenneis
 *
 */
public class BerkeleySocketImpl implements CKSocket {

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
	 * The Unix file descriptor.
	 */
	private int fd;

	/**
	 * 
	 */
	public BerkeleySocketImpl() {

		jniImpl = initialize();

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#bind(java.lang.String, int)
	 */
	@Override
	public native void bind(String hostname, int port) throws CKSocketException;

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#connect(java.lang.String, int)
	 */
	@Override
	public native void connect(String host, int port) throws CKSocketException;
	
	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#create(boolean)
	 */
	@Override
	public native void create(boolean stream) throws CKSocketException;

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#getHostname()
	 */
	@Override
	public native String getHostname();

	/**
	 * Initialize the JNI reference;
	 * 
	 * @return
	 */
	private native long initialize();

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#isConnected()
	 */
	@Override
	public native boolean isConnected();

	/* (non-Javadoc)
	 * @see java.net.SocketOptions#setOption(int, java.lang.Object)
	@Override
	public native void setOption(int optID, Object value) throws SocketException;
	 */
	
	/* (non-Javadoc)
	 * @see java.net.SocketOptions#getOption(int)
	@Override
	public native Object getOption(int optID) throws SocketException;
	 */

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#connect(java.net.InetAddress, int)
	 */
	//@Override
	protected void connect(InetAddress address, int port) throws IOException {

		nativeConnect(address.getHostAddress(), port, 0);

	}

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#connect(java.net.SocketAddress, int)
	 */
	//@Override
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

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#listen(int)
	 */
	@Override
	public native void listen(int backlog) throws CKSocketException;

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#accept()
	 */
	@Override
	public native CKSocket accept() throws CKSocketException;

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#getInputStream()
	@Override
	protected native InputStream getInputStream() throws IOException;
	 */

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#getOutputStream()
	@Override
	protected native OutputStream getOutputStream() throws IOException;
	 */

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#available()
	 */
	//@Override
	protected native int available() throws IOException;

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.jni.CKSocket#close()
	 */
	@Override
	public native void close();

	/* (non-Javadoc)
	 * @see java.net.SocketImpl#sendUrgentData(int)
	 */
	//@Override
	protected native void sendUrgentData(int data) throws IOException;
	
}
