/**
 * 
 */
package org.cryptokitty.provider.x509.der;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 */
public class DERInteger implements DERPrimitive<BigInteger> {

	/*
	 * Integer value.
	 */
	private BigInteger value;

	/**
	 * Constructor for decoding.
	 */
	public DERInteger() {
		this.value = null;
	}

	/**
	 * Constructor for encoding.
	 */
	public DERInteger(BigInteger value) {
		this.value = value;
	}

	@Override
	public int decode(byte[] encoded) throws EncodingException {

		if (encoded[0] != DERTags.ASN1_INTEGER_TAG) {
			throw new EncodingException("Invalid tag, not an integer");
		}

		// BER/DER encoding allows for the length encoding to be 127 octets
		// long. In Java, such a value is not possible. Integer encodings are
		// limited to 2^32 bytes.
		int length;
		int index;
		if ((encoded[1] & 0x80) == 0) {
			// Short form length
			length = encoded[1];
			index = 2;
		}
		else {
			// Long form length
			int lengthBytes = encoded[1] & 0x7f;
			if (lengthBytes > 4) {
				throw new EncodingException("Integer encoding length out of range");
			}
			BigInteger l = new BigInteger(1, Arrays.copyOfRange(encoded, 2, lengthBytes+2));
			length = (int)l.longValue();
			index = lengthBytes + 2;
		}

		byte[] vEncoding = Arrays.copyOfRange(encoded, index, index + length);
		value = new BigInteger(vEncoding);

		return index + length;

	}

	@Override
	public byte[] encode() throws EncodingException {

		byte[] v = value.toByteArray();
		byte[] answer;
		int index = 0;
		if (v.length < 128) {
			// Short form length
			answer = new byte[v.length + 2];
			answer[1] = (byte)v.length;
			index = 2;
		}
		else {
			int lCount = (v.length / 256) + 1;
			if (lCount > 4) {
				throw new EncodingException("Integer value out of range");
			}
			int vLength = v.length + 2 + lCount;
			answer = new byte[vLength];
			answer[1] = (byte)(lCount | 0x80);
			// We use BigInteger here because Scalar32 always encodes 4 bytes.
			// DER requires the fewest number of octets possible.
			BigInteger l = BigInteger.valueOf(lCount);
			byte[] ll = l.toByteArray();
			System.arraycopy(ll, 0, answer, 2, ll.length);
			index = ll.length + 2;
		}
		answer[0] = DERTags.ASN1_INTEGER_TAG;
		System.arraycopy(v, 0, answer, index, v.length);

		return answer;

	}

	@Override
	public BigInteger getValue() {
		return value;
	}

	
}
