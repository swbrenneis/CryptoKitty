/**
 * 
 */
package org.cryptokitty.provider.mac;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.cryptokitty.provider.BadParameterException;
import org.cryptokitty.provider.IllegalStateException;
import org.cryptokitty.provider.digest.Digest;
import org.cryptokitty.provider.random.FortunaSecureRandom;

/**
 * @author stevebrenneis
 *
 */
public class HMAC {

	/**
	 * Digest block size.
	 */
	private int B;
	
	/**
	 * Digest length
	 */
	private int L;

	/**
	 * Input mask pad.
	 */
	private byte[] ipad;

	/**
	 * Output mask pad.
	 */
	private byte[] opad;

	/**
	 * HMAC key.
	 */
	private byte[] K;

	/**
	 * Text to be validated.
	 */
	private byte[] text;

	/**
	 * Message digest.
	 */
	private Digest digest;

	/**
	 * 
	 * @param digest
	 */
	public HMAC(Digest digest) {

		this.digest = digest;
		B = digest.getBlockSize();
		L = digest.getDigestLength();
		ipad = new byte[B];
		Arrays.fill(ipad, (byte)0x36);
		opad = new byte[B];
		Arrays.fill(opad, (byte)0x5c);

	}

	/**
	 * Quick and dirty array append.
	 * @param a
	 * @param b
	 * @return
	 */
	private byte[] Append(byte[] a, byte[] b) {

		byte[] res = new byte[a.length + b.length];
		System.arraycopy(a, 0, res, 0, a.length);
		System.arraycopy(b, 0, res, a.length, b.length);
		return res;

	}

	/**
	 * 
	 * @param hmac
	 * @return
	 * @throws IllegalStateException 
	 * @throws BadParameterException 
	 */
	public boolean authenticate(byte[] hmac) throws BadParameterException, IllegalStateException {

		return Arrays.equals(getHMAC(), hmac);

	}

	/*
	 * Generate an HMAC key. The key size will be rounded
	 * to a byte boundary. The Key must be at least L bytes.
	 */
	public byte[] generateKey(int bitsize) throws BadParameterException {

		if (bitsize / 8 < L) {
			throw new BadParameterException("Invalid key size");
		}

		FortunaSecureRandom secure = new FortunaSecureRandom();
		K = new byte[bitsize / 8];
		secure.nextBytes(K);
		return K;

	}

	/**
	 * Generate the HMAC.
	 *
	 * H(K XOR opad, H(K XOR ipad, text))
	 * 
	 * @return
	 * @throws IllegalStateException 
	 * @throws BadParameterException 
	 */
	public byte[] getHMAC() throws IllegalStateException, BadParameterException {

		if (K.length == 0) {
			throw new IllegalStateException("Key not set");
		}

		// Pad or truncate the key until it is B bytes.
		byte[] k;
		if (K.length > B) {
			k = digest.digest(K);
		}
		else if (K.length < B) {
			ByteBuffer buf = ByteBuffer.allocate(B);
			byte[] pad = new byte[B - K.length];
			buf.put(pad);
			buf.put(K);
			k = buf.array();
		}
		else {
			k = K;
		}

		digest.reset();
		// First mask.
		byte[] i = Xor(k, ipad);
		i = Append(i, text);
		byte[] h1 = digest.digest(i);
		digest.reset();
		byte[] o = Xor(k, opad);
		o = Append(o, h1);
		return digest.digest(o);

	}

	/**
	 * 
	 * @return
	 */
	public long getDigestLength() {
		
		return digest.getDigestLength();

	}

	/**
	 * 
	 * Quick and dirty array xor.
	 * 
	 * @param a
	 * @param b
	 * @return
	 * @throws BadParameterException 
	 */
	private byte[] Xor(byte[] a, byte[] b) throws BadParameterException {

		if (a.length != b.length) {
			throw new BadParameterException("Array lengths for xor must be the same");
		}

		byte[] res = new byte[a.length];
		for (int i = 0; i < a.length; ++i) {
			res[i] = (byte)(a[i] ^ b[i]);
		}
		
		return res;

	}

	/**
	 * 
	 * @param k
	 * @throws BadParameterException 
	 */
	public void setKey(byte[] k) throws BadParameterException {

		if (k.length < L) {
			throw new BadParameterException("Invalid HMAC key");
		}

		K = k;

	}

	/**
	 * 
	 * @param m
	 */
	public void setMessage(byte[] m) {

		text = m;

	}

}
