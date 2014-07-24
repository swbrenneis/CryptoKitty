/**
 * 
 */
package org.cryptokitty.keys;

import java.nio.charset.Charset;

import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * Creates a simple hashed key. The passphrase is hashed according to the
 * hash algorithm value. The hash result is truncated or concatenated with
 * additional padded hashes to produce the desired key size. See RFC 4880,
 * section 3.7.1.1.
 * 
 * This method is NOT recommended since it is cryptographically weak. It
 * may be deprecated in the future.
 * 
 */
public class SimpleS2K extends String2Key {

	/**
	 *
	 */
	public SimpleS2K(String passPhrase, int algorithm) throws KeyException {
		super(passPhrase, algorithm);
		// Nothing to do here.
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#generateKey()
	 */
	@Override
	public byte[] generateKey(int bitsize) {

		Hash digest = null;
		try {
			digest = HashFactory.getDigest(algorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// This will have been taken care of in the constructor,
			// but just in case...
			System.err.println(e.getMessage());
		}
		if (digest == null) {
			return null;
		}

		byte[] pBytes = passPhrase.getBytes(Charset.forName("UTF-8"));
		return digest.digest(pBytes);

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		byte[] encoded = new byte[2];
		encoded[0] = 0;
		encoded[1] = (byte)algorithm;
		return encoded;
	}

}
