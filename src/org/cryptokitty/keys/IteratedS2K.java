/**
 * 
 */
package org.cryptokitty.keys;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptokitty.digest.Hash;
import org.cryptokitty.digest.HashFactory;

/**
 * @author Steve Brenneis
 *
 * Creates an iterated, salted, hashed key. The salt and passphrase are iteratively
 * added to a hashing context and hashed according to the hash algorithm value.
 * The hash result is truncated or concatenated with additional padded hashes to
 * produce the desired key size. See RFC 4880, section 3.7.1.2.
 * 
 */
public class IteratedS2K extends String2Key {

	/*
	 * Hashing salt.
	 */
	private byte[] salt;

	/*
	 * Count derivative. See RFC 4880, section 3.7.1.3
	 */
	private int c;

	/*
	 * Iterative count value. This is not a count of iterations, per se.
	 * It is the number of times that the salt + passphrase bytes are fed
	 * to the digest. 
	 */
	private int count;

	/**
	 * 
	 */
	public IteratedS2K(int algorithm, byte[] salt, int c)
			throws UnsupportedAlgorithmException {
		super(null, algorithm);
		// Salt is always 8 bytes.
		if (salt.length != 8) {
			this.salt = Arrays.copyOf(salt, 8);
		}
		else {
			this.salt = salt;
		}

		this.c = c;
		// Now calculate count. This is really lovely. The RFC gives no particular
		// reason for this algorithm.
		count = (byte)((16 + (c & 0x0f)) << ((c >> 4) +6));
	}

	/**
	 * 
	 */
	public IteratedS2K(String passPhrase, byte algorithm, byte[] salt)
			throws UnsupportedAlgorithmException {
		super(passPhrase, algorithm);
		// Salt is always 8 bytes.
		if (salt.length != 8) {
			this.salt = Arrays.copyOf(salt, 8);
		}
		else {
			this.salt = salt;
		}

		// It seems that the initial value of c is arbitrary, so we'll use
		// a non-zero random number.
		c = 0;
		while (c == 0) {
			c = (byte)(new SecureRandom().nextInt() & 0xff);
		}
		// Now calculate count. This is really lovely. The RFC gives no particular
		// reason for this algorithm.
		count = (byte)((16 + (c & 0x0f)) << ((c >> 4) +6));
	}

	/*
	 * Create the iterative hash context. We are not iteratively feeding the hash
	 * result to the digest. We are creating an array of salt + passphrase times
	 * the iteration count.
	 */
	private byte[] createDigestContext() {
		byte[] pass = passPhrase.getBytes(Charset.forName("UTF-8"));
		int feed = salt.length + pass.length;
		int fill = (feed) * count;
		byte[] hashContext = new byte[fill];
		int filled = 0;
		while (filled < fill) {
			System.arraycopy(salt, 0, hashContext, filled, salt.length);
			filled = salt.length;
			System.arraycopy(pass, 0, hashContext, filled, pass.length);
			filled = pass.length;
		}
		return hashContext;
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#generateKey(int)
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

		int keysize = bitsize / 8;
		int hashsize = digest.getDigestLength();
		byte[] context = createDigestContext();
		if (keysize == hashsize) {
			// Good to go.
			return digest.digest(context);
		}
		else if (keysize < hashsize) {
			// Truncate to left-most (most significant) bytes.
			byte[] hash = digest.digest(context);
			return Arrays.copyOfRange(hash, 0, keysize-1);
		}
		else {
			// Figure out how many hashes we need.
			int hashes = keysize / hashsize;
			if (keysize % hashsize > 0) {
				hashes++;
			}
			// See the RFC, section 3.7.1.3 for a description of this nasty
			// bit of business.
			byte[] key = new byte[keysize];
			// The first hash is not padded.
			byte[] hash = digest.digest(context);
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
				// Add the passphrase.
				hash = digest.digest(context);
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
		byte[] encoded = new byte[11];
		encoded[0] = 3;
		encoded[1] = (byte)algorithm;
		System.arraycopy(salt, 0, encoded, 2, 8);
		encoded[10] = (byte)c;
		return encoded;
	}

}
