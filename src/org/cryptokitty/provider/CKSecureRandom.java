/**
 * 
 */
package org.cryptokitty.provider;

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
 */
@SuppressWarnings("serial")
public class CKSecureRandom extends SecureRandomSpi {

	/*
	 * Random constants
	 */
	private static int i = 4095;
	private static final long r = 0xfffffffe; 
	private static final BigInteger a = BigInteger.valueOf(18782L);
	private static final long[] Q;

	static {
		// First time initialization will be expensive, but more secure
		// than hard-coding Q.
		Q = new long[4096];
		Random rnd = new Random(System.currentTimeMillis());
		for (int q = 0; q < 4096; ++q) {
			Q[q] = rnd.nextLong();
		}
	}

	/*
	 * Seed. c < 809430660.
	 */
	private long c;

	/**
	 * 
	 */
	public CKSecureRandom() {
		// Pick a random c to start with. May be modified in the set
		// seed method.
		c = System.currentTimeMillis() % 809430659;
		// This prevents an attacker from taking advantage of fast processors
		// to grab c. The Thread sleep period is not exact.
		try {
			Thread.sleep(200);
		}
		catch (InterruptedException e) {
			// Don't care.
		}
		c = (c + System.currentTimeMillis()) % 809430659;
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
		c = new BigInteger(seed).mod(BigInteger.valueOf(809430659)).longValue();
	}

	/* (non-Javadoc)
	 * @see java.security.SecureRandomSpi#engineNextBytes(byte[])
	 */
	@Override
	protected void engineNextBytes(byte[] bytes) {
		BigInteger random = BigInteger.valueOf(cmwc4096());
		byte[] b = random.toByteArray();
		while (b.length < bytes.length) {
			random = random.multiply(BigInteger.valueOf(cmwc4096()));
			b = random.toByteArray();
		}
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

}
