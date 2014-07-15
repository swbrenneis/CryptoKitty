/**
 * 
 */
package org.cryptokitty.data;

/**
 * @author Steve Brenneis
 *
 * Exception used for all data encoding and format errors.
 * 
 */
@SuppressWarnings("serial")
public class DataException extends Exception {

	/**
	 * 
	 */
	public DataException() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 */
	public DataException(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param cause
	 */
	public DataException(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 */
	public DataException(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public DataException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

}
