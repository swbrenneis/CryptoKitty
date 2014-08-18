/**
 * 
 */
package org.cryptokitty.pgp.packet;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class PacketException extends Exception {

	/**
	 * 
	 */
	public PacketException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public PacketException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public PacketException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public PacketException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public PacketException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

}
