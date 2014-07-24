/**
 * 
 */
package org.cryptokitty.provider;

import java.security.Provider;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class CryptoKittyProvider extends Provider {

	/*
	 * Provider information.
	 */
	private static final String INFO = "CryptoKitty Provider v0.1";

	/**
	 * 
	 */
	public CryptoKittyProvider() {
		super("CryptoKitty", 0.1, INFO);

		/* AccessController.doPrivileged(new java.security.PrivilegedAction() {
            public Object run() {
            	
            }
		}); */

	}

}
