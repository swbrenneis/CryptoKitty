/**
 * 
 */
package org.cryptokitty.provider.x509.der;

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
