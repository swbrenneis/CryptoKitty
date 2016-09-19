/**
 * 
 */
package org.cryptokitty.xprovider.keys;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.cryptokitty.digest.SHA1;
import org.cryptokitty.digest.SHA224;
import org.cryptokitty.digest.SHA256;
import org.cryptokitty.digest.Digest;
import org.cryptokitty.exceptions.BadParameterException;
import org.cryptokitty.xprovider.random.BBSSecureRandom;

/**
 * @author Steve Brenneis
 *
 * Implements the FIPS-186-4 DSA prime parameter generation algorithm.
 */
public class DSAParameterGenerator {

	/*
	 * BigInteger constants.
	 */
	// private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1L);
	private static final BigInteger TWO = BigInteger.valueOf(2L);
	// private static final BigInteger THREE = BigInteger.valueOf(3L);
	// private static final BigInteger FOUR = BigInteger.valueOf(4L);
	// private static final BigInteger FIVE = BigInteger.valueOf(5L);
	// private static final BigInteger SEVEN = BigInteger.valueOf(7L);
	// private static final BigInteger EIGHT = BigInteger.valueOf(8L);

	/*
	 * Generated counter. Will be 4L.
	 */
	private int counter;

	/*
	 * Hash function.
	 */
	private Digest digest;

	/*
	 * Domain parameter seed.
	 */
	private byte[] domainParameterSeed;

	/*
	 * Public key generator.
	 */
	private BigInteger g;

	/*
	 * Key size.
	 */
	private int L;

	/*
	 * Digest size.
	 */
	private int N;

	/*
	 * The prime p.
	 */
	private BigInteger p;
	
	/*
	 * Miller-Rabin primality test iterations for p.
	 */
	private int pIter;

	/*
	 * The prime divisor q.
	 */
	private BigInteger q;

	/*
	 * Miller-Rabin primality test iterations for q.
	 */
	private int qIter;

	/*
	 * Secure random for various functions.
	 */
	private SecureRandom random;

	/*
	 * Domain seed length.
	 */
	private int seedlen;

	/**
	 * 
	 */
	public DSAParameterGenerator(int L, int N, int seedlen)
			throws BadParameterException {
		
		if (L == 1024 && N == 160) {
			digest = new SHA1();
			pIter = qIter = 40;
		}
		else if (L == 2048 & N == 224) {
			digest = new SHA224();
			pIter = qIter = 56;
		}
		else if (L == 2048 & N == 256) {
			digest = new SHA256();
			pIter = qIter = 56;
		}
		else if (L == 3072 & N == 256) {
			digest = new SHA256();
			pIter = qIter = 64;
		}
		else {
			throw new BadParameterException("Unsupported key/hash size");
		}

		if (seedlen < N) {
			throw new BadParameterException("Invalid seed length");
		}

		this.L = L;
		this.N = N;
		this.seedlen = seedlen;
		domainParameterSeed = new byte[seedlen/8];
		random = new BBSSecureRandom();

	}

	/*
	 * Create the public key generator.
	 */
	private void createGenerator(BigInteger index) {

		BigInteger pp = p.subtract(BigInteger.ONE);
		BigInteger e = pp.divide(q);

		BigInteger count = BigInteger.ZERO;
		g = BigInteger.ZERO;
		byte[] ggen;
		try {
			ggen = "ggen".getBytes("UTF-8");
		}
		catch (UnsupportedEncodingException e1) {
			throw new RuntimeException("Unsupported character set: UTF-8");
		}
		while (g.compareTo(TWO) < 0) {
			digest.reset();
			count = count.add(BigInteger.ONE);
			int dLen = domainParameterSeed.length;
			int iLen = index.bitLength() / 8;
			int cLen = count.bitLength() / 8;
			byte[] U = new byte [dLen + 4 + iLen + cLen];
			System.arraycopy(domainParameterSeed, 0, U, 0, dLen);
			System.arraycopy(ggen, 0, U, dLen, 4);
			System.arraycopy(index.toByteArray(), 0, U, dLen+4, iLen);
			System.arraycopy(count.toByteArray(), 0, U, dLen+4+iLen, cLen);
			BigInteger W = new BigInteger(1, digest.digest(U));
			g = W.modPow(e, p);
		}

	}

	/*
	 * Generate the DSA domain parameters.
	 */
	public void generateParameters(long index) {

		generatePrimes();
		createGenerator(BigInteger.valueOf(index));

	}

	/*
	 * Generate and validate the primes
	 */
	private void generatePrimes() {

		// FIPS-186 says outlen shall be greater than or equal to N
		int outlen = N;
		// Why, oh why would the Java ceil function return a double?
		// And, isn't this the same as n = Math.floor((double)L/outlen)?
		int n = (int)Math.ceil((double)L/outlen) - 1;
		int b = L - 1 - (n * outlen);

		// Generate q.
		random.nextBytes(domainParameterSeed);
		BigInteger modulusN = TWO.pow(N-1);
		// Get the remainder, to create the prime such that 2**(N-1) < q <= 2**N
		BigInteger U = new BigInteger(1, digest.digest(domainParameterSeed)).mod(modulusN);
		// q = 2**N-1 + U + 1 - (U mod 2). This will ensure that the prime is odd.
		q = modulusN.add(U).add(BigInteger.ONE).subtract(U.mod(TWO));
		while (!isPrime(q, qIter)) {
			// try again
			random.nextBytes(domainParameterSeed);
			digest.reset();
			U = new BigInteger(1, digest.digest(domainParameterSeed)).mod(modulusN);
			q = modulusN.add(U).add(BigInteger.ONE).subtract(U.mod(TWO));
		}

		// Generate p
		int offset = 1;
		counter = 0;
		boolean pPrime = false;
		BigInteger[] V = new BigInteger[n+1];
		while (counter < 4 * L && !pPrime) {
			for (int j = 0; j <= n; ++j) {
				digest.reset();
				BigInteger dps = new BigInteger(1, domainParameterSeed);
				BigInteger encOffest = BigInteger.valueOf(offset);
				BigInteger encJ = BigInteger.valueOf(j);
				BigInteger vj = dps.add(encOffest).add(encJ).mod(TWO.pow(seedlen));
				V[j] = new BigInteger(1, digest.digest(vj.toByteArray()));
			}
			// W = V0 + (V1 * 2^outlen) + ... + (Vn-1 * 2^((n-1) * outlen)) + ((Vn mod 2^b) * 2^(n * outlen)).
			BigInteger W = V[0];
			for (int v = 1; v < n; ++v) {
				W = W.add(V[v]).multiply(TWO.pow(v*outlen));
			}
			// Umm. Wow.
			W = W.add(V[n]).mod(TWO.pow(b)).multiply(TWO.pow(n * outlen));
			BigInteger X = W.add(TWO.pow(L-1));
			BigInteger c = X.mod(TWO.multiply(q));
			p = X.subtract(c.subtract(BigInteger.ONE));
			if (p.compareTo(TWO.pow(N-1)) < 0) {
				offset += n + 1;
				counter++;
			}
			else {
				if (isPrime(p, pIter)) {
					pPrime = true;
				}
				else {
					offset += n + 1;
					counter++;
				}
			}
		}
		if (!pPrime) {
			// Start over.
			generatePrimes();
		}

		if (!validatePrimes()) {
			generatePrimes();
		}

	}

	/*
	 * Get the generator g.
	 */
	public BigInteger getG() {
		return g;
	}

	/*
	 * Get the prime p.
	 */
	public BigInteger getP() {
		return p;
	}

	/*
	 * Get the prime divisor q.
	 */
	public BigInteger getQ() {
		return q;
	}

	/*
	 * Test for prime.
	 */
	private boolean isPrime(BigInteger x, int iter) {
		return millerRabin(x, iter);
	}

	/*
	 * Miller-Rabin test for primes. Returns true if probably prime,
	 * false if composite.
	 */
	private boolean millerRabin(BigInteger w, int iter) {

		// Select a such that 2**a is the largest integer that
		// divides w-1.
		BigInteger ww = w.subtract(BigInteger.ONE);
		int a = ww.bitLength();
		while (!ww.remainder(TWO.pow(a)).equals(BigInteger.ZERO)) {
			a--;
		}
		BigInteger m = ww.divide(TWO.pow(a));
		int wlen = w.bitLength();
		byte[] bb = new byte[wlen/8];
		for (int i = 1; i <= iter; ++i) {
			random.nextBytes(bb);
			BigInteger b = new BigInteger(1, bb);
			while (b.equals(BigInteger.ONE) || b.compareTo(ww) >= 0) {
				random.nextBytes(bb);
				b = new BigInteger(1, bb);
			}
			BigInteger z = b.modPow(m, w);
			if (!z.equals(BigInteger.ONE) && !z.equals(ww)) {
				int j = 1;
				boolean cont = false;
				while (j < a && !cont) {
					z = z.modPow(TWO, w);
					if (z.equals(BigInteger.ONE)) {
						return false;
					}
					cont = z.equals(ww);
					j++;
				}
				if (!cont) {
					return false;
				}
			}
		}

		return true;

	}

	/*
	 * Validate the primes.
	 */
	private boolean validatePrimes() {

		int ll = p.bitLength();
		if (ll != L) {
			return false;
		}

		int nn = q.bitLength();
		if (nn != N) {
			return false;
		}

		if (counter >= 4 * L) {
			return false;
		}

		if (domainParameterSeed.length * 8 < N) {
			return false;
		}

		digest.reset();
		BigInteger U = new BigInteger(digest.digest(domainParameterSeed)).mod(TWO.pow(N-1));
		BigInteger computed_q = TWO.pow(N-1).add(U).add(BigInteger.ONE).subtract(U.mod(TWO));
		if (!isPrime(computed_q, qIter) || !q.equals(computed_q)) {
			return false;
		}

		int outlen = N;
		int n = (int)Math.ceil((double)L/outlen) - 1;
		int b = L - 1 - (n * outlen);

		int offset = 1;
		int i = 0;
		boolean pPrime = false;
		BigInteger[] V = new BigInteger[n+1];
		BigInteger computed_p = BigInteger.ZERO;
		while (i <= counter && !pPrime) {
			for (int j = 0; j <= n; ++j) {
				digest.reset();
				BigInteger dps = new BigInteger(1, domainParameterSeed);
				BigInteger encOffest = BigInteger.valueOf(offset);
				BigInteger encJ = BigInteger.valueOf(j);
				BigInteger vj = dps.add(encOffest).add(encJ).mod(TWO.pow(seedlen));
				V[j] = new BigInteger(1, digest.digest(vj.toByteArray()));
			}
			// W = V0 + (V1 * 2^outlen) + ... + (Vn-1 * 2^((n-1) * outlen)) + ((Vn mod 2^b) * 2^(n * outlen)).
			BigInteger W = V[0];
			for (int v = 1; v < n; ++v) {
				W = W.add(V[v]).multiply(TWO.pow(v*outlen));
			}
			// Umm. Wow.
			W = W.add(V[n]).mod(TWO.pow(b)).multiply(TWO.pow(n * outlen));
			BigInteger X = W.add(TWO.pow(L-1));
			BigInteger c = X.mod(TWO.multiply(q));
			computed_p = X.subtract(c.subtract(BigInteger.ONE));
			if (computed_p.compareTo(TWO.pow(N-1)) < 0) {
				offset += n + 1;
				i++;
			}
			else {
				if (isPrime(computed_p, pIter)) {
					pPrime = true;
				}
				else {
					offset += n + 1;
					i++;
				}
			}
		}
		if (i != counter || !computed_p.equals(p)) {
			return false;
		}

		return true;

	}

}
