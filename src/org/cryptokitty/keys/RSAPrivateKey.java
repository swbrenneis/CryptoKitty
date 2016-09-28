/**
 * 
 */
package org.cryptokitty.keys;

import java.security.PrivateKey;

import org.cryptokitty.jni.BigInteger;
import org.cryptokitty.exceptions.SignatureException;
import org.cryptokitty.exceptions.IllegalBlockSizeException;

/**
 * @author Steve Brenneis
 *
 * The inheritance tree of the RSA key and cipher classes is such
 * a mess because Java doesn't provide a sensible differentiation
 * between RSA modulus private key and RSA Chinese Remainder Theorem
 * private keys.
*/
public abstract class RSAPrivateKey implements PrivateKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = 428700186656349706L;

	/**
	 * Key size.
	 */
	protected int bitsize;

	/**
	 * Default constructor
	 */
	protected RSAPrivateKey() {
	}

	/**
	 * Return the size of the key.
	 * 
	 * @return
	 */
	public int getBitsize() {
		return bitsize;
	}
	
	/**
	 * Signature primitive.
	 * 
	 * @param m
	 * @return
	 * @throws SignatureException
	 */
	public abstract BigInteger rsasp1(BigInteger m) throws SignatureException;

	/**
	 * Decryption primitive.
	 * 
	 * @param c
	 * @return
	 * @throws IllegalBlockSizeException
	 */
	public abstract BigInteger rsadp(BigInteger c) throws IllegalBlockSizeException;

	/*
	 * (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return "RSA";
	}

	/*
	 * (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

}
