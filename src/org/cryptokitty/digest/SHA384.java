/**
 * 
 */
package org.cryptokitty.digest;

import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 */
public class SHA384 extends SHA512 {

	/**
	 * 
	 */
	public SHA384() {

		// Set the initial hash values for SHA384
		H1 = 0xcbbb9d5dc1059ed8L;
		H2 = 0x629a292a367cd507L;
		H3 = 0x9159015a3070dd17L;
		H4 = 0x152fecd8f70e5939L;
		H5 = 0x67332667ffc00b31L;
		H6 = 0x8eb44a8768581511L;
		H7 = 0xdb0c2e0d64f98fa7L;
		H8 = 0x47b5481dbefa4fa4L;

	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.CKSHA512#finalize(byte[])
	 */
	@Override
	protected byte[] finalize(byte[] message) {
		byte[] m = super.finalize(message);
		return Arrays.copyOf(m, 48);
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.Digest#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		return 48;
	}

}
