/**
 * 
 */
package org.cryptokitty.jni;

import org.cryptokitty.exceptions.CKSocketException;

/**
 * @author stevebrenneis
 *
 */
public class CKSocketFactory {

	/**
	 * 
	 */
	public CKSocketFactory() {
	}

	public static CKSocket createTCPSocket() throws CKSocketException {

		CKSocket socket = new BerkeleySocketImpl();
		socket.create(true);
		return socket;

	}

	public static CKSocket createUDPSocket() throws CKSocketException {

		CKSocket socket = new BerkeleySocketImpl();
		socket.create(false);
		return socket;

	}

}
