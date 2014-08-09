/**
 * 
 */
package org.cryptokitty.provider;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class BadParameterException extends Exception {

	/**
	 * 
	 */
	public BadParameterException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public BadParameterException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public BadParameterException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public BadParameterException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public BadParameterException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

}
