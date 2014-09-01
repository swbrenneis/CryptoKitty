/**
 * 
 */
package org.cryptokitty.provider.signature;

import org.cryptokitty.provider.ProviderException;

/**
 * @author Steve Brenneis
 *
 * Basic signature exception with a single message.
 */
@SuppressWarnings("serial")
public class SignatureException extends ProviderException {

	/**
	 * 
	 */
	public SignatureException() {
		super("Signature error");
	}

}
