/**
 * 
 */
package org.cryptokitty.keys;

import java.nio.charset.Charset;

import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashValue;

/**
 * @author Steve Brenneis
 *
 * Creates a simple hashed key. The passphrase is hashed according to the
 * hash algorithm value. The hash result is truncated or concatenated with
 * a second hash to produce the desired key size. See RFC 4880,
 * section 3.7.1.1.
 */
public class SimpleS2K extends String2Key {

	/**
	 * @param passPhrase
	 * @param algorithm
	 * @throws KeyException
	 */
	public SimpleS2K(String passPhrase, byte algorithm) throws KeyException {
		super(passPhrase, algorithm);
		// Nothing to do here.
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#generateKey()
	 */
	@Override
	public byte[] generateKey(int bitsize) {
		byte[] pass = passPhrase.getBytes(Charset.forName("UTF-8"));
		Hash digest = null;
		try {
			digest = HashValue.getDigest(algorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// This will have been taken care of in the constructor,
			// but just in case...
			System.err.println(e.getMessage());
		}
		if (digest == null) {
			return null;
		}

		int keysize = bitsize / 8;
		byte[] key = new byte[keysize];
		int hashsize = digest.getDigestLength();
		byte[] hash = digest.digest(pass);
		
		return null;
		
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		byte[] encoded = new byte[2];
		encoded[0] = 0;
		encoded[1] = algorithm;
		return encoded;
	}

}
