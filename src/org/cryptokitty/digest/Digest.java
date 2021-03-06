/**
 * 
 */
package org.cryptokitty.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

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

	/**
	 * 
	 * @return
	 */
	public abstract int getBlockSize();

	/**
	 * Get the length of the hash in bytes.
	 * 
	 * @return
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
