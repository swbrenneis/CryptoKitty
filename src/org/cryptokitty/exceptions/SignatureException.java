/**
 * 
 */
package org.cryptokitty.exceptions;

/**
 * @author stevebrenneis
 *
 */
public class SignatureException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2025689678794058812L;

	/**
	 * 
	 */
	public SignatureException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public SignatureException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public SignatureException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public SignatureException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public SignatureException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

}
