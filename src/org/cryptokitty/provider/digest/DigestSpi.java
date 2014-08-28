/**
 * 
 */
package org.cryptokitty.provider.digest;

import java.security.MessageDigestSpi;

/**
 * @author Steve Brenneis
 *
 */
public class DigestSpi extends MessageDigestSpi {

	/*
	 * The digest
	 */
	private Digest digest;

	/**
	 * 
	 */
	protected DigestSpi(Digest digest) {
		this.digest = digest;
	}

	/* (non-Javadoc)
	 * @see java.security.MessageDigestSpi#engineUpdate(byte)
	 */
	@Override
	protected void engineUpdate(byte input) {
		digest.update(input);
	}

	/* (non-Javadoc)
	 * @see java.security.MessageDigestSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		digest.update(input, offset, len);
	}

	/* (non-Javadoc)
	 * @see java.security.MessageDigestSpi#engineDigest()
	 */
	@Override
	protected byte[] engineDigest() {
		return digest.digest();
	}

	/* (non-Javadoc)
	 * @see java.security.MessageDigestSpi#engineReset()
	 */
	@Override
	protected void engineReset() {
		digest.reset();
	}

}
