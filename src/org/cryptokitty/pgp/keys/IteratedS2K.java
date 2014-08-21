/**
 * 
 */
package org.cryptokitty.pgp.keys;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptokitty.pgp.AlgorithmFactory;
import org.cryptokitty.provider.UnsupportedAlgorithmException;
import org.cryptokitty.provider.digest.Digest;

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
	 * Exponent bias for calculating hashing iterations.
	 */
	private static final int EXPBIAS = 6;

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
	private long count;

	/**
	 * 
	 */
	public IteratedS2K(String passPhrase, int algorithm, byte[] salt, int c)
			throws UnsupportedAlgorithmException {
		super(passPhrase, algorithm);
		// Salt is always 8 bytes.
		this.salt = Arrays.copyOf(salt, 8);

		this.c = c;
		// Now calculate count. This is really lovely. The RFC gives no particular
		// reason for this algorithm.
		count = ((16 + (c & 0x0f)) << ((c >> 4) + EXPBIAS));
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
		count = ((16 + (c & 0x0f)) << ((c >> 4) + EXPBIAS));
	}

	/*
	 * Create the iterative hash context. We are not iteratively feeding the hash
	 * result to the digest. We are creating an array of salt + passphrase times
	 * the iteration count.

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
	 */
	/* (non-Javadoc)
	 * @see org.cryptokitty.keys.String2Key#generateKey(int)
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
			return null;
		}

		// This is going to be ugly.
		int keysize = bitsize / 8;
		int hashsize = digest.getDigestLength();
		// Number of hash contexts needed
		int numhashes = (keysize + (hashsize - 1)) / hashsize;
		Digest[] hashes = new Digest[numhashes];
		// Always need one
		hashes[0] = digest;
		for (int i = 1; i < numhashes; ++i) {
			try {
				hashes[i] = AlgorithmFactory.getDigest(algorithm);
			}
			catch (UnsupportedAlgorithmException e) {
				// We did this once.
			}
			// Pad the hash contexts with zeros, second context = 1, third = 2, etc.
			byte[] pad = new byte[i];
			Arrays.fill(pad, (byte)0);
			hashes[i].update(pad);
		}

		byte[] pBytes = passPhrase.getBytes(Charset.forName("UTF-8"));
		byte[] toHash = new byte[salt.length + pBytes.length];
		System.arraycopy(salt, 0, toHash, 0, salt.length);
		System.arraycopy(pBytes, 0, toHash, salt.length, pBytes.length);
		
		// All contexts will be updated with the full salt + passphrase.
		for (int i = 0; i < numhashes; ++i) {
			hashes[i].update(toHash);
		}

		// Index is a byte count. Repeatedly hash the salt + passPhrase until the
		// specified number of bytes have been digested.
		long index = count - toHash.length;
		while (index > 0) {
			for (int i = 0; i < numhashes; ++i) {
				hashes[i].update(Arrays.copyOf(toHash,
									(int)Math.min(toHash.length, index)));
			}
			index -= toHash.length;
		}
		if (keysize <= hashsize) {
			// Key is leftmost (MSB) bytes.
			return Arrays.copyOf(hashes[0].digest(), keysize);
		}
		else {
			// Hashes are copied serially until the key if filled.
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
		byte[] encoded = new byte[11];
		encoded[0] = 3;
		encoded[1] = (byte)algorithm;
		System.arraycopy(salt, 0, encoded, 2, 8);
		encoded[10] = (byte)c;
		return encoded;
	}

}
