/**
 * 
 */
package org.cryptokitty.pgp.keys;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class KeyException extends Exception {

	/**
	 * 
	 */
	public KeyException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public KeyException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public KeyException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public KeyException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public KeyException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

}
