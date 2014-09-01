/**
 * 
 */
package org.cryptokitty.provider.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.cryptokitty.provider.UnsupportedAlgorithmException;

/**
 * @author Steve Brenneis
 *
 * Basic interface contract for all Crypto Kitty hashes.
 */
public abstract class Digest {

	/*
	 * Message accumulator.
	 */
	private ByteArrayOutputStream accumulator;

	/**
	 * 
	 */
	protected Digest() {
		accumulator = new ByteArrayOutputStream();
	}

	/*
	 * Finish a previously updated digest.
	 */
	public byte[] digest() {
		byte[] result = finalize(accumulator.toByteArray());
		accumulator.reset();
		return result;
	}

	/*
	 * One step hash. Previous updates to the context are ignored.
	 */
	public byte[] digest(byte[] message) {
		try {
			accumulator.write(message);
			return digest();
		} catch (IOException e) {
			// Nope
			throw new RuntimeException(e);
		}
	}

	/*
	 * Finalize the digest.
	 */
	protected abstract byte[] finalize(byte[] message);

	/*
	 * Get a digest class from a string.
	 */
	public static Digest getInstance(String algorithm)
			throws UnsupportedAlgorithmException {

		switch (algorithm) {
		case "MD5":
			return new CKMD5();
		case "RIPEMD-160":
			return new CKRIPEMD160();
		case "SHA-1":
			return new CKSHA1();
		case "SHA-224":
			return new CKSHA224();
		case "SHA-256":
			return new CKSHA256();
		case "SHA-384":
			return new CKSHA384();
		case "SHA-512":
			return new CKSHA512();
		default:
			throw new UnsupportedAlgorithmException("Unsupported digest: "
															+ algorithm);
		}

	}

	/*
	 * Get the length of the hash in bytes.
	 */
	public abstract int getDigestLength();

	/*
	 * Reset the accumulator. Accumulated input is discarded.
	 */
	public void reset() {
		accumulator.reset();
	}

	/*
	 * Update the hash context.
	 */
	public void update(byte message) {
		accumulator.write(message);
	}

	/*
	 * Update the hash context.
	 */
	public void update(byte[] message) {
		try {
			accumulator.write(message);
		}
		catch (IOException e) {
			// Meh.
			throw new RuntimeException(e);
		}
	}

	/*
	 * Update the hash context.
	 */
	public void update(byte[] message, int offset, int length) {
		accumulator.write(message, offset, length);
	}

}
