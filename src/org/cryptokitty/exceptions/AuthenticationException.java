/**
 * 
 */
package org.cryptokitty.exceptions;

/**
 * @author stevebrenneis
 *
 */
public class AuthenticationException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2812621655451609248L;

	/**
	 * 
	 */
	public AuthenticationException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public AuthenticationException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public AuthenticationException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public AuthenticationException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public AuthenticationException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

}
