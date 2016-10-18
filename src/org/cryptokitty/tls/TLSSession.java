/**
 * 
 */
package org.cryptokitty.tls;

import org.cryptokitty.exceptions.TLSException;

/**
 * @author stevebrenneis
 *
 */
public class TLSSession {

	/**
	 * 
	 */
	protected TLSSession() {
		// TODO Auto-generated constructor stub
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
	public native long receiveRecord(byte[] record, long length);

	/**
	 * Send a TLS application record.
	 * 
	 * @param record
	 */
	public native void sendRecord(byte[] record) throws TLSException;

	/**
	 * Set the certificate credentials for this session.
	 * 
	 * @param credentials
	 * @throws TLSException
	 */
	public native void setCredentials(TLSCredentials credentials) throws TLSException;

	/**
	 * Start the Berkeley sockets transport.
	 * 
	 * @param socket Open socket file descriptor
	 * @return
	 */
	public native boolean startSocketTransport(int socket);

	/**
	 * Terminate the TLS connection.
	 */
	public native void tlsBye();

}
