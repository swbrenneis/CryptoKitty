/**
 * 
 */
package org.cryptokitty.test;

import java.security.Key;

/**
 * @author Steve Brenneis
 *
 * A general purpose Key interface implementation for testing purposes
 * only.
 */
final class TestKey implements Key {

	/*
	 * Raw key material.
	 */
	private byte[] key;
	
	/**
	 * 
	 */
	public TestKey(byte[] key) {
		this.key = key;
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return "Test";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return "Raw";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		return key;
	}

}
