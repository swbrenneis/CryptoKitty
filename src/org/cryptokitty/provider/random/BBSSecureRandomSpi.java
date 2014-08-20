/**
 * 
 */
package org.cryptokitty.provider.random;

import java.math.BigInteger;
import java.security.SecureRandomSpi;

import org.cryptokitty.data.Scalar64;

/**
 * @author Steve Brenneis
 *
 * Implements the Blum Blum Shub PRNG. Provides a very secure RNG but is
 * somewhat slow.
 * 
 * For a faster but less secure RNG use the Complimentary Multiplication
 * With Carry (CMWC) class.
 */
@SuppressWarnings("serial")
public class BBSSecureRandomSpi extends SecureRandomSpi {

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
	 * The state.
	 */
	private BigInteger X;

	/**
	 * 
	 */
	public BBSSecureRandomSpi() {
		M = null;
	}

	/*
	 * Initialize the generator state.
	 */
	private void initialize() {

		CMWCRandom rnd = new CMWCRandom();
		BigInteger p = new BigInteger(512, 100, rnd);
		// Check for congruence to 3 (mod 4). Generate new prime if not.
		while (p.mod(FOUR).compareTo(THREE) != 0) {
			p = new BigInteger(512, 20, rnd);
		}
		BigInteger q = new BigInteger(512, 100, rnd);
		// Check for inequality and congruence
		while  (p.compareTo(q) == 0 || q.mod(FOUR).compareTo(THREE) != 0) {
			q = new BigInteger(512, 100, rnd);
		}
		// Compute the modulus
		M = p.multiply(q);
		// Compute the initial seed.
		byte[] seed = Scalar64.encode(System.nanoTime());
		setState(seed);

	}

	/*
	 * Calculate the state using the given seed. We use the given seed to seed
	 * the RNG to generate the prime. X must be coprime with M. Note that
	 * only 64 bits of the seed are used, so long seeds are pointless.
	 */
	private void setState(byte[] seed) {

		CMWCRandom rnd = new CMWCRandom();
		rnd.setSeed(new BigInteger(seed).longValue());
		X = new BigInteger(64, 100, rnd);
		while (X.gcd(M).compareTo(BigInteger.ONE) != 0) {
			X = new BigInteger(64, 100, rnd);
		}

	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineSetSeed(byte[])
	 */
	@Override
	protected void engineSetSeed(byte[] seed) {
		// Does nothing. Prevents known input attacks.
	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineNextBytes(byte[])
	 */
	@Override
	protected void engineNextBytes(byte[] bytes) {

		if (M == null) {
			initialize();
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