/**
 * 
 */
package org.cryptokitty.provider;

/**
 * @author Steve Brenneis
 *
 * This is the base class exception for all encryption, decryption, and
 * signature exceptions, including encoding exceptions. It is provided
 * to simplify method signatures. 
 */
@SuppressWarnings("serial")
public class ProviderException extends Exception {

	/**
	 * 
	 */
	public ProviderException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public ProviderException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public ProviderException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public ProviderException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public ProviderException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

}
