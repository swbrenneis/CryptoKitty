/**
 * 
 */
package org.cryptokitty.provider.random;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import org.cryptokitty.provider.digest.CKSHA256;

/**
 * @author Steve Brenneis
 *
 * Quick source of entropy for initializing various secure items.
 */
@SuppressWarnings("serial")
public class CMWCRandom extends Random {

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
	 * Random seed.
	 */
	private long seed;

	/**
	 * 
	 */
	public CMWCRandom() {
		Q = null;
		seed = System.nanoTime();
	}

	/**
	 * @param seed
	 */
	public CMWCRandom(long seed) {
		Q = null;
		this.seed = seed;
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

	/*
	 * (non-Javadoc)
	 * @see java.util.Random#next(int)
	 */
	@Override
	protected int next(int bits) {
		if (Q == null) {
			seedGenerator();
		}
		long mask = 0;
		for (int m = 0; m < bits; ++m) {
			mask = mask << 1;
			mask = mask | 1;
		}
		return (int)(cmwc4096() & mask);
	}

	/*
	 * Seed the generator.
	 */
	private void seedGenerator() {
		Q = new long[4096];
		byte[] fill = new byte[4096 * 8];
		CKSHA256 digest = new CKSHA256();
		long nonce = seed;
		byte[] context = null;
		int filled = 0;
		while (filled < 4096) {
			if (context != null) {
				digest.update(context);
			}
			digest.update(BigInteger.valueOf(nonce).toByteArray());
			nonce++;
			BigInteger l = BigInteger.valueOf(System.nanoTime());
			digest.update(l.toByteArray());
			context = digest.digest();
			System.arraycopy(context, 0, fill, filled * 8, context.length);
			filled += context.length;
		}
		for (int q = 0; q < 4096; ++q) {
			Q[q] = new BigInteger(Arrays.copyOfRange(fill, q, q + 8)).longValue();
		}
		c = System.nanoTime() % 809430659;
		// Reset the reseed counter.
	}

	@Override
	public void setSeed(long seed) {
		this.seed = seed;
		seedGenerator();
	}

}
