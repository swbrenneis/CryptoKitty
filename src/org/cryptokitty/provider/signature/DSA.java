/**
 * 
 */
package org.cryptokitty.provider.signature;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 */
public class DSA {

	/*
	 * The message digest.
	 */
	private MessageDigest digest;

	/*
	 * RNG for calculating k
	 */
	private SecureRandom random;

	/**
	 * @throws NoSuchAlgorithmException 
	 * 
	 */
	public DSA(String algorithm, SecureRandom random)
			throws NoSuchAlgorithmException {
		digest = MessageDigest.getInstance(algorithm);
		this.random = random;
	}

	/*
	 * Sign a message. There are a lot of constraints placed on the
	 * value of k, and the constraints cascade. We'll handle this with
	 * recursion
	 */
	public BigInteger[] sign(DSAPrivateKey key, byte[] M) {

		BigInteger x = key.getX();
		DSAParams params = key.getParams();
		BigInteger q = params.getQ();
		BigInteger p = params.getP();
		BigInteger g = params.getG();

		// Calculate per-message random k
		int bitLength = q.bitLength();
		BigInteger k = new BigInteger(bitLength, random);
		while (k.compareTo(q) >= 0) {
			k = new BigInteger(bitLength, random);
		}
		// Modular inverse of k
		BigInteger k1 = k.modInverse(q);

		// Calculate r.
		BigInteger r = g.modPow(k, p).mod(q);
		if (r.equals(BigInteger.ZERO)) {
			// This is unlikely.
			return sign(key, M);
		}

		byte[] m = digest.digest(M);
		int N = q.bitLength();
		// Should usually be the same.
		int len = Math.max(N, digest.getDigestLength());
		BigInteger z = new BigInteger(1, Arrays.copyOf(m, len));

		// s = (k1 * (z + (x * r))) mod q
		BigInteger s = k1.multiply(z.add(x.multiply(r))).mod(q);
		if (s.equals(BigInteger.ZERO)) {
			// If s == 0, start over with new k
			return sign(key, M);
		}

		BigInteger[] result = {r, s};
		return result;

	}

	/*
	 * Verify a signature.
	 */
	public boolean verify(DSAPublicKey key, byte[] M, BigInteger[] S) {

		BigInteger y = key.getY();
		DSAParams params = key.getParams();
		BigInteger p = params.getP();
		BigInteger q = params.getQ();
		BigInteger g = params.getG();

		// S[0] = r, S[1] = s.
		BigInteger r = S[0];
		BigInteger s = S[1];

		if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0
				|| s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(q) >= 0) {
			return false;
		}

		BigInteger w = s.modInverse(q);
		
		byte[] m = digest.digest(M);
		int N = q.bitLength();
		// Should usually be the same.
		int len = Math.max(N, digest.getDigestLength());
		BigInteger z = new BigInteger(1, Arrays.copyOf(m, len));

		BigInteger u1 = w.multiply(z).mod(q);
		BigInteger u2 = w.multiply(r).mod(q);
	
		// The algorithm is (((g**u1) * (y**u2)) mod p) mod q
		// There is no exponentiation method for BigInteger that takes a
		// BigInteger. This takes advantage of the distributive nature of
		// modular arithmetic:
		// ((a % c) * (b % c)) % c == (a * b) % c.
		BigInteger qq = g.modPow(u1, p);
		BigInteger yy = y.modPow(u2, p);
		BigInteger v = qq.multiply(yy).mod(p).mod(q);

		return r.equals(v);

	}

}
