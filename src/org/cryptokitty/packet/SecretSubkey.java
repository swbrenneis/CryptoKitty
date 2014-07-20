/**
 * 
 */
package org.cryptokitty.packet;

import java.io.InputStream;

/**
 * @author Steve Brenneis
 *
 * The contents of a secret subkey are identical to a secret key.
 * THis class is here just for differentiation. It may disappear.
 */
public class SecretSubkey extends SecretKey {

	/**
	 * @param in
	 * @throws InvalidPacketException
	 */
	public SecretSubkey(InputStream in) throws InvalidPacketException {
		super(in);
		// TODO Auto-generated constructor stub
	}

}
