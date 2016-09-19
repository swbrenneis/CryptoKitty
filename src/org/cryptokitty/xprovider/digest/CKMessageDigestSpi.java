/**
 * 
 */
package org.cryptokitty.xprovider.digest;

import java.security.MessageDigestSpi;

import org.cryptokitty.digest.Digest;

/**
 * @author Steve Brenneis
 *
 */
public class CKMessageDigestSpi extends MessageDigestSpi {

	/*
	 * The digest
	 */
	protected Digest digest;

	/**
	 * 
	 */
	protected CKMessageDigestSpi() {
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
