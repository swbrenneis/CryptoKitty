/**
 * 
 */
package org.cryptokitty.provider.keys;

import java.math.BigInteger;
import java.security.SignatureException;

import javax.crypto.IllegalBlockSizeException;

/**
 * @author Steve Brenneis
 *
 * The inheritance tree of the RSA key and cipher classes is such
 * a mess because Java doesn't provide a sensible differentiation
 * between RSA modulus private key and RSA Chinese Remainder Theorem
 * private keys.
*/
public abstract class CKRSAPrivateKey {

	/*
	 * Key size.
	 */
	protected int bitsize;

	/**
	 * Default constructor
	 */
	protected CKRSAPrivateKey() {
	}

	/*
	 * Return the size of the key.
	 */
	public int getBitsize() {
		return bitsize;
	}
	
	/*
	 * Signature primitive.
	 */
	public abstract BigInteger rsasp1(BigInteger m)
						throws SignatureException;

	/*
	 * Decryption primitive.
	 */
	public abstract BigInteger rsadp(BigInteger c)
						throws IllegalBlockSizeException;

}
