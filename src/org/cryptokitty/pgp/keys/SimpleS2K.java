/**
 * 
 */
package org.cryptokitty.pgp.keys;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.cryptokitty.digest.Digest;
import org.cryptokitty.pgp.AlgorithmFactory;
import org.cryptokitty.xprovider.UnsupportedAlgorithmException;

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
	public SimpleS2K(String passPhrase, int algorithm)
			throws UnsupportedAlgorithmException {
		super(passPhrase, algorithm);
		// Nothing to do here.
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#generateKey()
	 */
	@Override
	public byte[] generateKey(int bitsize) {

		Digest digest = null;
		try {
			digest = AlgorithmFactory.getDigest(algorithm);
		}
		catch (UnsupportedAlgorithmException e) {
			// This will have been taken care of in the constructor,
			// but just in case...
			System.err.println(e.getMessage());
		}
		if (digest == null) {
			return null;
		}

		// This is going to be ugly.
		int keysize = bitsize / 8;
		int hashsize = digest.getDigestLength();
		int numhashes = (bitsize / hashsize) + (bitsize % hashsize != 0 ? 1 : 0);
		Digest[] hashes = new Digest[numhashes];
		hashes[0] = digest;
		for (int i = 1; i < numhashes; ++i) {
			byte[] pad = new byte[i];
			Arrays.fill(pad, (byte)0);
			try {
				hashes[i] = AlgorithmFactory.getDigest(algorithm);
			}
			catch (UnsupportedAlgorithmException e) {
				// We did this once.
			}
			hashes[i].update(pad);
		}
		byte[] pBytes = passPhrase.getBytes(Charset.forName("UTF-8"));
		for (int i = 0; i < numhashes; ++i) {
			hashes[i].update(pBytes);
		}
		if (keysize <= hashsize) {
			return Arrays.copyOf(hashes[0].digest(), keysize);
		}
		else {
			int remain = keysize;
			byte[] key = new byte[keysize];
			for (int i = 0; i < numhashes; ++i) {
				System.arraycopy(hashes[i].digest(), 0, key, i*hashsize,
												Math.min(remain, hashsize));
				remain -= hashsize;
			}
			return key;
		}

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
