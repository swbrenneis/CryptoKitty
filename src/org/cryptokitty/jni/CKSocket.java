/**
 * 
 */
package org.cryptokitty.jni;

import org.cryptokitty.exceptions.CKSocketException;

/**
 * @author stevebrenneis
 *
 */
public interface CKSocket {

	/**
	 * Accept a new client connection.
	 * 
	 * @return
	 * @throws CKSocketException
	 */
	public CKSocket accept() throws CKSocketException;

	/**
	 * Bind the socket to the address and port.
	 * 
	 * @param address
	 * @param port
	 * @throws CKSocketException
	 */
	public void bind(String address, int port) throws CKSocketException;

	/**
	 * Close the socket.
	 */
	public void close();

	/**
	 * Connect to the specified address and port.
	 * 
	 * @param address
	 * @param port
	 */
	public void connect(String address, int port) throws CKSocketException;

	/**
	 * Create a socket.
	 * 
	 * @param stream Create a TCP socket if true, else create a
	 * UDP socket
	 */
	public void create(boolean stream) throws CKSocketException;

	/**
	 * Return the address associated with this socket.
	 * 
	 * @return
	 */
	public String getHostname();

	/**
	 * 
	 * @return
	 */
	public boolean isConnected();

	/**
	 * Listen for client connections.
	 * 
	 * @param backlog
	 * @throws CKSocketException
	 */
	public void listen(int backlog) throws CKSocketException;

}
