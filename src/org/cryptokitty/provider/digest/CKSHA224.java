/**
 * 
 */
package org.cryptokitty.provider.digest;

/**
 * @author Steve Brenneis
 *
 */
public class CKSHA224 extends CKSHA256 {

	/**
	 * 
	 */
	public CKSHA224() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * (non-Javadoc)
	 * @see org.cryptokitty.provider.digest.CKSHA256#getDigestLength()
	 */
	@Override
	public int getDigestLength() {
		return 30;
	}

}
