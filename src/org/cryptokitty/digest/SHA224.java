/**
 * 
 */
package org.cryptokitty.digest;

import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 */
public class SHA224 extends SHA256 {

	/**
	 * 
	 */
	public SHA224() {

		// Set the initial hash values for SHA224
		H1 = 0xc1059ed8;
		H2 = 0x367cd507;
		H3 = 0x3070dd17;
		H4 = 0xf70e5939;
		H5 = 0xffc00b31;
		H6 = 0x68581511;
		H7 = 0x64f98fa7;
		H8 = 0xbefa4fa4;

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.CKSHA256#finalize(byte[])
	 */
	@Override
	protected byte[] finalize(byte[] message) {
		byte[] m = super.finalize(message);
		return Arrays.copyOf(m, 28);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.CKSHA256#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		return 28;
	}

}
