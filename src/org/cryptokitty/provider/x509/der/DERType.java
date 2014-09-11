/**
 * 
 */
package org.cryptokitty.provider.x509.der;

import org.cryptokitty.provider.EncodingException;

/**
 * @author Steve Brenneis
 *
 */
public interface DERType {

	/*
	 * Basic encode.
	 */
	public byte[] encode() throws EncodingException;

	/*
	 * Basic decode. Returns the number of decoded octets.
	 */
	public int decode(byte[] encoded) throws EncodingException;

}
