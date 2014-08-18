/**
 * 
 */
package org.cryptokitty.provider.random;

import java.math.BigInteger;
import java.security.SecureRandomSpi;
import java.util.Random;

/**
 * @author Steve Brenneis
 *
 * Complimentary multiply with carry PRNG. Extremely high k
 * and period. k = 4097 and period = 2^13110.
 * 
 * Taken from the May 2003 Communications of the ACM.
 * 
 * Provides a measure of security because its period is so long
 * and the randomizer arrays is very large and randomly generated.
 * In order to hide the fact that the numbers generated are pseudo-
 * random, the generator is re-seeded after every 900 Kbytes.
 * 
 * If a more secure, but slower implementation is needed, use the
 * Blum Blum Shub class.
 * 
 */
@SuppressWarnings("serial")
public class CMWCSecureRandom extends SecureRandomSpi {

	/*
	 * Random constants
	 */
	private static int i = 4095;
	private static final long r = 0xfffffffe; 
	private static final BigInteger a = BigInteger.valueOf(18782L);

	/*
	 * Mask c < 809430660.
	 */
	private long c;

	/*
	 * Random seed.
	 */
	private long[] Q;

	/*
	 * Re-seeding counter.
	 */
	private long reseed;

	/**
	 * 
	 */
	public CMWCSecureRandom() {
		// Seed Q and set the reseed counter.
		reseed();
		// Pick a random c to start with. May be modified in the set
		// seed method.
		c = System.nanoTime() % 809430659;
	}

	/*
	 * The PRNG. This looks like C because it was adapted from a C
	 * implementation.
	 */
	private long cmwc4096() {

		BigInteger t;
		BigInteger x;
		BigInteger ci = BigInteger.valueOf(c);

		i = (i + 1) & 4095;
		BigInteger q = BigInteger.valueOf(Q[i]);
		t = a.multiply(q).add(ci);
		ci = t.shiftRight(32);
		x = t.add(ci);
		c = ci.longValue();
		if (x.compareTo(ci) < 0) {
			x = x.add(BigInteger.ONE);
			c++;
		}

		return (Q[i] = r - x.longValue());

	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineSetSeed(byte[])
	 */
	@Override
	protected void engineSetSeed(byte[] seed) {
		// The seed isn't directly used in the algorithm. It is
		// used to seed a Java Random object to populate Q and c.
		Random rnd = new Random(new BigInteger(seed).longValue());
		for (int q = 0; q < 4096; ++q) {
			Q[q] = rnd.nextLong();
		}
		// Reset the reseed counter.
		reseed = 900 * 1024;
	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineNextBytes(byte[])
	 */
	@Override
	protected void engineNextBytes(byte[] bytes) {
		// Check for re-seeding.
		if (reseed - bytes.length <= 0) {
			reseed();
		}
		BigInteger random = BigInteger.valueOf(cmwc4096());
		byte[] b = random.toByteArray();
		while (b.length < bytes.length) {
			random = random.multiply(BigInteger.valueOf(cmwc4096()));
			b = random.toByteArray();
		}
		// Decrement the reseed counter.
		reseed -= bytes.length;
		System.arraycopy(b, 0, bytes, 0, bytes.length);
	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineGenerateSeed(int)
	 */
	@Override
	protected byte[] engineGenerateSeed(int numBytes) {
		byte[] next = new byte[numBytes];
		engineNextBytes(next);
		return next;
	}

	/*
	 * Reseed the generator.
	 */
	private void reseed() {
		Random rnd = new Random(System.nanoTime());
		for (int q = 0; q < 4096; ++q) {
			Q[q] = rnd.nextLong();
		}
		c = System.nanoTime() % 809430659;
		// Reset the reseed counter.
		reseed = 900 * 1024;
	}

}
