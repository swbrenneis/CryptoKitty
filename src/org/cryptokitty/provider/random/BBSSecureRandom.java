/**
 * 
 */
package org.cryptokitty.provider.random;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Random;

/**
 * @author Steve Brenneis
 *
 * Implements the Blum Blum Shub PRNG. Provides a very secure RNG but is
 * somewhat slow. The generator is re-seeded every 900 Kbytes of output
 * to hide psuedo-randomness.
 * 
 * For a faster but less secure RNG use the Complimentary Multiplication
 * With Carry (CMWC) class.
 */
@SuppressWarnings("serial")
public class BBSSecureRandom extends SecureRandomSpi {

	/*
	 * BigInteger constants.
	 */
	private static final BigInteger TWO = BigInteger.valueOf(2L);
	private static final BigInteger THREE = BigInteger.valueOf(3L);
	private static final BigInteger FOUR = BigInteger.valueOf(4L);

	/*
	 * The modulus.
	 */
	private BigInteger M;

	/*
	 * Reseed counter.
	 */
	private int reseed;

	/* 
	 * The seed.
	 */
	private BigInteger X;

	/**
	 * 
	 */
	public BBSSecureRandom() {
		M = null;
	}

	/*
	 * Initialize the generator state.
	 */
	private void initialize() {

		BigInteger p = new BigInteger(512, 100, new Random());
		// Check for congruence to 3 (mod 4). Generate new prime if not.
		while (p.mod(FOUR).compareTo(THREE) != 0) {
			p = new BigInteger(512, 20, new Random());
		}
		BigInteger q = new BigInteger(512, 100, new Random());
		// Check for inequality and congruence
		while  (p.compareTo(q) == 0 || q.mod(FOUR).compareTo(THREE) != 0) {
			q = new BigInteger(512, 100, new Random());
		}
		// Compute the modulus
		M = p.multiply(q);
		// Seed the generator and reset the reseed counter.
		reseed();

	}

	/*
	 * Calculate the seed. It needs to be coprime with M so we
	 * will use the input to seed the RNG used to create the prime.
	 * We will start with a seed of a small bit magnitude to generate
	 * as many randoms as possible before hitting the modulus. The
	 * method resets the algorithm to the X n-1 state.
	 */
	private void reseed() {

		try {
			SecureRandom rnd = SecureRandom.getInstance("CMWC", "CryptoKitty");
			X = new BigInteger(64, 100, rnd);
			while (X.gcd(M).compareTo(BigInteger.ONE) != 0) {
				X = new BigInteger(64, 100, rnd);
			}
		}
		catch (NoSuchAlgorithmException e) {
			// Not happening.
		}
		catch (NoSuchProviderException e) {
			// Not happening.
		}

		reseed = 900 * 1024;

	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineSetSeed(byte[])
	 */
	@Override
	protected void engineSetSeed(byte[] seed) {

		try {
			SecureRandom rnd = SecureRandom.getInstance("CMWC", "CryptoKitty");
			rnd.setSeed(seed);
			X = new BigInteger(64, 100, rnd);
			while (X.gcd(M).compareTo(BigInteger.ONE) != 0) {
				X = new BigInteger(64, 100, rnd);
			}
		}
		catch (NoSuchAlgorithmException e) {
			// Not happening.
		}
		catch (NoSuchProviderException e) {
			// Not happening.
		}

		reseed = 900 * 1024;

	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineNextBytes(byte[])
	 */
	@Override
	protected void engineNextBytes(byte[] bytes) {
		if (M == null) {
			initialize();
		}
		// Check for re-seeding.
		else if (reseed - bytes.length <= 0) {
			reseed();
		}

		X = X.modPow(TWO, M);	// X(n) = X(n-1)**2 mod M.
		int bitLength = X.bitLength();
		int byteCount = bytes.length;

		while (byteCount >= 0) {
			// Count bits to make a byte.
			byte thisByte = 0;
			for (int b = 0; b < 8; ++b) {
				thisByte = (byte)(thisByte << 1);
				// Parity test.
				int parity = 0;
				for (int l = 0; l < bitLength; ++l) {
					if (X.testBit(l)) {
						++parity;
					}
				}
				// Gosling is a boob.
				// If parity is even, set the bit
				thisByte = (byte)(thisByte | (byte)(parity % 2 == 0 ? 1 : 0));
				X.shiftRight(1);
				bitLength--;
				if (bitLength == 0) {
					// We ran out of bits. Need another random.
					X = X.modPow(TWO, M);
					// This is an unsigned operation. Not really important.
					bitLength = X.bitLength();
				}
			}
			bytes[--byteCount] = thisByte;
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineGenerateSeed(int)
	 */
	@Override
	protected byte[] engineGenerateSeed(int numBytes) {
		byte[] seed = new byte[numBytes];
		engineNextBytes(seed);
		return seed;
	}

}
