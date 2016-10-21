/**
 * 
 */
package org.cryptokitty.tls;

import java.net.Socket;

import org.cryptokitty.exceptions.TLSException;
import org.cryptokitty.jni.CKSocket;

/**
 * @author stevebrenneis
 *
 */
public class TLSSession {

	/**
	 * Load the CryptoKitty-C binary.
	 */
	static {
		System.loadLibrary("ckjni");
	}

	/**
	 * JNI implementation index.
	 */
	private long jniImpl;

	/**
	 * 
	 */
	protected TLSSession() {
	}

	/**
	 * Free JNI resources.
	 */
	private native void dispose();

	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#finalize()
	 */
	@Override
	public void finalize() throws Throwable {

		dispose();

	}

	/**
	 * Perform the TLS handshake.
	 * 
	 * @return
	 */
	public native boolean doHandshake();

	/**
	 * 
	 * @return The connected hostname for this session
	 */
	public native String getHostname();

	/**
	 * Get the certificate validation error.
	 * 
	 * @return
	 */
	public native String getCertificateError();

	/**
	 * 
	 * @return The error message for the last failed operation.
	 */
	public native String getLastError();

	/**
	 * 
	 * @return A TLS client session.
	 * @throws TLSException
	 */
	public static native TLSSession initializeClient() throws TLSException;

	/**
	 * 
	 * @return A TLS server session.
	 * @throws TLSException
	 */
	public static native TLSSession initializeServer() throws TLSException;

	/**
	 * Get a TLS application record. This call may block depending on the
	 * underlying transport.
	 * 
	 * @param record
	 * @param length
	 * @return
	 */
	public native long receiveRecord(byte[] record, long length) throws TLSException;

	/**
	 * Send a TLS application record.
	 * 
	 * @param record
	 */
	public native void sendRecord(byte[] record) throws TLSException;

	/**
	 * Set the connected hostname for this session.
	 * 
	 * @param hostname
	 */
	public native void setHostname(String hostname);

	/**
	 * Set the certificate credentials for this session.
	 * 
	 * @param credentials
	 * @throws TLSException
	 */
	public native void setCredentials(TLSCredentials credentials) throws TLSException;

	/**
	 * 
	 * @param require
	 */
	public native void setRequireClientAuth(boolean require);

	/**
	 * Start the Berkeley sockets transport.
	 * 
	 * @param socket Open socket file descriptor
	 * @return
	 */
	public native boolean startSocketTransport(CKSocket socket);

	/**
	 * Terminate the TLS connection.
	 */
	public native void tlsBye();

}
