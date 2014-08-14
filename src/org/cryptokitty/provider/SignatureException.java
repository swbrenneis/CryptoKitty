/**
 * 
 */
package org.cryptokitty.provider;

/**
 * @author Steve Brenneis
 *
 * Non-oracle exception.
 */
@SuppressWarnings("serial")
public class SignatureException extends Exception {

	/**
	 * 
	 */
	public SignatureException() {
		super("Signature error");
	}

}
