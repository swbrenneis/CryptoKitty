/**
 * 
 */
package org.cryptokitty.provider.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * @author stevebrenneis
 *
 */
public class CKRIPEMD160 implements Digest {

	/*
	 * Message accumulator.
	 */
	private ByteArrayOutputStream accumulator;

	/**
	 * 
	 */
	public CKRIPEMD160() {
		accumulator = new ByteArrayOutputStream();
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#digest()
	 */
	@Override
	public byte[] digest() {
		return digest(accumulator.toByteArray());
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#digest(byte[])
	 */
	@Override
	public byte[] digest(byte[] message) {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * Non-linear functions.
	 */
	private int f(int j, int x, int y, int z) {
		if (j <= 15) {
			return x ^ y ^ z;
		}
		else if (j <= 31) {
			return (x & y ) | ((~x) & z);
		}
		else if (j <= 47) {
			return (x | (~y)) ^ z;
		}
		else if (j <= 63) {
			return (x & z) | (y & (~z));
		}
		else {
			return x ^ (y | (~z));
		}
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		return 20;
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#update(byte)
	 */
	@Override
	public void update(byte message) {
		accumulator.write(message);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#update(byte[])
	 */
	@Override
	public void update(byte[] message) {
		try {
			accumulator.write(message);
		}
		catch (IOException e) {
			// Nope.
			throw new RuntimeException(e);
		}
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#update(byte[], int, int)
	 */
	@Override
	public void update(byte[] message, int offset, int length) {
		accumulator.write(message, offset, length);
	}

}
