/**
 * 
 */
package org.cryptokitty.provider.x509.der;

/**
 * @author Steve Brenneis
 *
 */
public class DERTags {

	/*
	 * Tag constant
	 */
	public static final int ASN1_INTEGER_TAG = 2;

	/**
	 * 
	 */
	public DERTags() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * Return a typed DER object.
	 */
	public static DERType getDERType(int tag)
			throws EncodingException {

		switch(tag) {
		case ASN1_INTEGER_TAG:
			return new DERInteger();
		default:
			throw new EncodingException("Invalid tag");
		}

	}

	/*
	 * Decode a tag number.
	 */
	public static int getTag(byte[] encoded) {

		if ((encoded[0] & 0x1f) == 0x1f) {
			// Long form tag
			int index = 1;
			int tag = 0;
			while ((encoded[index] & 0x80) != 0) {
				tag = (tag << 8) | encoded[index++];
			}
			tag = tag << 8 | (encoded[index] & 0x7f);
			return tag;
		}
		else {
			// Short form tag.
			return encoded[0] & 0x1f;
		}

	}

}
