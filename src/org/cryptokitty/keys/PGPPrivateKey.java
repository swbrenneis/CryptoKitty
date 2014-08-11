/**
 * 
 */
package org.cryptokitty.keys;

import java.security.PrivateKey;

import org.cryptokitty.packet.SecretKeyPacket;

/**
 * @author Steve Brenneis
 *
 */
@SuppressWarnings("serial")
public class PGPPrivateKey implements PrivateKey {

	/*
	 * Key algorithm.
	 */
	private int algorithm;

	/**
	 * 
	 */
	public PGPPrivateKey(SecretKeyPacket packet) {
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		switch (algorithm) {
		case KeyAlgorithms.DSA:
			return "DSA";
		case KeyAlgorithms.RSA:
		case KeyAlgorithms.RSA_SIGN:
		case KeyAlgorithms.RSA_ENCRYPT:
			return "RSA";
		case KeyAlgorithms.ELGAMAL:
			return "ElGamal";
		default:
			return "";
		}
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getFormat()
	 */
	@Override
	public String getFormat() {
		return "RAW";
	}

	/* (non-Javadoc)
	 * @see java.security.Key#getEncoded()
	 */
	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

}
