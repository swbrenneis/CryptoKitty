/**
 * 
 */
package org.cryptokitty.keys;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * Creates a salted, hashed key. The salt and passphrase are hashed according
 * to the hash algorithm value. The hash result is truncated or concatenated
 * with additional padded hashes to produce the desired key size. See RFC 4880,
 * section 3.7.1.2.
 * 
 */
public class SaltedS2K extends String2Key {

	/*
	 * Hashing salt.
	 */
	private byte[] salt;

	/**
	 * 
	 */
	public SaltedS2K(int algorithm, byte[] salt)
			throws UnsupportedAlgorithmException {
		super(null, algorithm);
		// Salt is always 8 bytes.
		if (salt.length != 8) {
			this.salt = Arrays.copyOf(salt, 8);
		}
		else {
			this.salt = salt;
		}
	}

	/**
	 * 
	 */
	public SaltedS2K(String passPhrase, int algorithm, byte[] salt)
			throws UnsupportedAlgorithmException {
		super(passPhrase, algorithm);
		// Salt is always 8 bytes.
		if (salt.length != 8) {
			this.salt = Arrays.copyOf(salt, 8);
		}
		else {
			this.salt = salt;
		}
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#generateKey(int)
	 */
	@Override
	public byte[] generateKey(int bitsize) {

		// It probably isn't necessary to UTF-8 encode this, but we
		// will do it for consistency with the RFC.
		byte[] pass = passPhrase.getBytes(Charset.forName("UTF-8"));
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

		int keysize = bitsize / 8;
		int hashsize = digest.getDigestLength();
		if (keysize == hashsize) {
			// Good to go.
			digest.update(salt);
			return digest.digest(pass);
		}
		else if (keysize < hashsize) {
			// Truncate to left-most (most significant) bytes.
			digest.update(salt);
			byte[] hash = digest.digest(pass);
			return Arrays.copyOfRange(hash, 0, keysize-1);
		}
		else {
			// Figure out how many hashes we need.
			int hashes = keysize / hashsize;
			if (keysize % hashsize > 0) {
				hashes++;
			}
			// See the RFC, section 3.7.1.2 for a description of this nasty
			// bit of business.
			byte[] key = new byte[keysize];
			// The first hash is not padded.
			digest.update(salt);
			byte[] hash = digest.digest(pass);
			digest.reset();
			System.arraycopy(hash, 0, key, 0, hashsize);
			// Get indexes and sizes ready for the iterative padding.
			hashes--;
			int pad = 1;
			int pos = hashsize;
			int size = keysize - hashsize;
			// Generate hashes to fill the remainder of the key.
			while (hashes > 0) {
				// Create the byte array of zeros for padding the digest.
				byte[] padding = new byte[pad];
				Arrays.fill(padding, (byte)0);
				// Add the padding to the digest.
				digest.update(padding);
				// Add the salt.
				digest.update(salt);
				// Add the passphrase.
				hash = digest.digest(pass);
				digest.reset();
				// Copy the full or partial has result into the key.
				System.arraycopy(hash, 0, key, pos, size);
				// Update all the indexes and sizes.
				hashes--;
				pos += hashsize;
				size -= hashsize;
				pad++;
			}
			return key;
		}

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		byte[] encoded = new byte[10];
		encoded[0] = 1;
		encoded[1] = (byte)algorithm;
		System.arraycopy(salt, 0, encoded, 2, 8);
		return encoded;
	}

}
