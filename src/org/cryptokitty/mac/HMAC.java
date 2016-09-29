/**
 * 
 */
package org.cryptokitty.mac;

import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.exceptions.IllegalStateException;

/**
 * @author stevebrenneis
 *
 */
public class HMAC {

	/**
	 * Digest sizes.
	 */
	public static final int SHA224 = 224;
	public static final int SHA256 = 256;
	public static final int SHA384 = 384;
	public static final int SHA512 = 512;

	/**
	 * JNI implemetation pointer.
	 */
	private long pointer;

	/**
	 * 
	 * @param digest
	 */
	public HMAC(int digest) throws BadParameterException {

		switch (digest) {
		case SHA224:
		case SHA256:
		case SHA384:
		case SHA512:
			initialize(digest);
			break;
		default:
			throw new BadParameterException("Invalid digest type");
		}

	}

	/**
	 * 
	 * @param hmac
	 * @return
	 * @throws IllegalStateException 
	 * @throws BadParameterException 
	 */
	public native boolean authenticate(byte[] hmac)
					throws BadParameterException, IllegalStateException;

	/**
	 * Generate an HMAC key. The key size will be rounded
	 * to a byte boundary. The Key must be at least L bytes.
	 * 
	 * @param bitsize
	 * @return
	 * @throws BadParameterException
	 */
	public native byte[] generateKey(int bitsize) throws BadParameterException;

	/**
	 * Generate the HMAC.
	 *
	 * H(K XOR opad, H(K XOR ipad, text))
	 * 
	 * @return
	 * @throws IllegalStateException 
	 * @throws BadParameterException 
	 */
	public native byte[] getHMAC() throws IllegalStateException, BadParameterException;
	
	/**
	 * 
	 * @return
	 */
	public native long getDigestLength();

	/**
	 * 
	 * @param digest
	 */
	private native void initialize(int digest);

	/**
	 * 
	 * @param k
	 * @throws BadParameterException 
	 */
	public native void setKey(byte[] k) throws BadParameterException;

	/**
	 * 
	 * @param m
	 */
	public native void setMessage(byte[] m);

}
