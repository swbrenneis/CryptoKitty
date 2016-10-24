/**
 * 
 */
package org.cryptokitty.codec;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * @author stevebrenneis
 *
 * This ugly mess is used to convert a CryptoKitty BigInteger
 * to a Java BigInteger. CryptoKitty BigIntegers are always
 * positive, so they don't have the sign byte.
 */
public class BigIntegerConverter {

	/**
	 * Encoding availability flags. Used for lazy encoding.
	 */
	private boolean ceAvailable;
	private boolean jeAvailable;
	private boolean ciAvailable;
	private boolean jiAvailable;

	/**
	 * The encoded CryptoKitty BigInteger value.
	 */
	private byte[] ckEncoded;

	/**
	 * The encoded Java BigInteger value.
	 */
	private byte[] javaEncoded;

	/**
	 * CryptoKitty BigInteger.
	 */
	private org.cryptokitty.jni.BigInteger ckInteger;

	/**
	 * Java BigInteger.
	 */
	private java.math.BigInteger javaInteger;

	/**
	 * Construct with a Java BigInteger.
	 * 
	 * @param integer
	 */
	public BigIntegerConverter(java.math.BigInteger integer) {

		jiAvailable = true;
		ciAvailable = ceAvailable = jeAvailable = false;
		javaInteger = integer;

	}

	/**
	 * Construct with a CryptoKitty BigInteger.
	 * 
	 * @param integer
	 */
	public BigIntegerConverter(org.cryptokitty.jni.BigInteger integer) {

		ciAvailable = true;
		jiAvailable = ceAvailable = jeAvailable = false;
		ckInteger = integer;

	}

	/**
	 * Construct with an encoded value.
	 * 
	 * @param encoded
	 * @param ckEncoding True if the encoding is in CryptoKitty format.
	 */
	public BigIntegerConverter(byte[] encoded, boolean ckEncoding) {

		ceAvailable = ckEncoding;
		jeAvailable = !ckEncoding;
		jiAvailable = ciAvailable = false;
		
		if (ckEncoding) {
			ckEncoded = encoded;
		}
		else {
			javaEncoded = encoded;
		}

	}

	/**
	 * Safe encoding permutation. CryptoKitty encoded to Java encoded.
	 */
	private void ce2je() {

		if (ceAvailable) {
			ByteBuffer buf = ByteBuffer.allocate(ckEncoded.length + 1);
			buf.put((byte)0);
			buf.put(ckEncoded);
			javaEncoded = buf.array();
			jeAvailable = true;
		}

	}

	/**
	 * Safe encoding permutation. CryptoKitty encoded to Java integer.
	 * Also provides Java encoding.
	 */
	private void ce2ji() {

		if (ceAvailable) {
			ByteBuffer buf = ByteBuffer.allocate(ckEncoded.length + 1);
			buf.put((byte)0);
			buf.put(ckEncoded);
			javaEncoded = buf.array();
			javaInteger = new java.math.BigInteger(javaEncoded);
			jeAvailable = jiAvailable = true;
		}

	}

	/**
	 * Safe encoding permutation. CryptoKitty integer to Java Integer.
	 * Also provides Java and CryptoKitty encodings.
	 */
	private void ci2je() {

		if (ciAvailable) {
			ckEncoded = ckInteger.getEncoded();
			ByteBuffer buf = ByteBuffer.allocate(ckEncoded.length + 1);
			buf.put((byte)0);
			buf.put(ckEncoded);
			javaEncoded = buf.array();
			jeAvailable = ceAvailable = true;
		}

	}

	/**
	 * Safe encoding permutation. CryptoKitty integer to Java Integer.
	 * Provides all encodings.
	 */
	private void ci2ji() {

		if (ciAvailable) {
			ckEncoded = ckInteger.getEncoded();
			ByteBuffer buf = ByteBuffer.allocate(ckEncoded.length + 1);
			buf.put((byte)0);
			buf.put(ckEncoded);
			javaEncoded = buf.array();
			javaInteger = new java.math.BigInteger(javaEncoded);
			ciAvailable = jeAvailable = ceAvailable = true;
		}

	}

	/**
	 * Safe encoding permutation. Java integer to CryptoKitty encoding.
	 * Also provides CryptoKitty encoding.
	 */
	private void je2ci() {

		if (jeAvailable) {
			ckEncoded = Arrays.copyOfRange(javaEncoded, 1, javaEncoded.length);
			ckInteger = new org.cryptokitty.jni.BigInteger(ckEncoded);
			ceAvailable = ciAvailable = true;
		}

	}

	/**
	 * Safe encoding permutation. Java encoding to CryptoKitty encoding.
	 */
	private void je2ce() {

		if (jeAvailable) {
			ckEncoded = Arrays.copyOfRange(javaEncoded, 1, javaEncoded.length);
			ceAvailable = true;
		}
	}

	/**
	 * Safe encoding permutation. Java integer to CryptoKitty encoding.
	 * Also provides Java and CryptoKitty encodings.
	 */
	private void ji2ce() {

		if (jiAvailable) {
			javaEncoded = javaInteger.toByteArray();
			ckEncoded = Arrays.copyOfRange(javaEncoded, 1, javaEncoded.length);
			ceAvailable = jeAvailable = true;
		}

	}

	/**
	 * Safe encoding permutation. Java integer to CryptoKitty integer.
	 * Provides all encodings.
	 */
	private void ji2ci() {

		if (jiAvailable) {
			javaEncoded = javaInteger.toByteArray();
			ckEncoded = Arrays.copyOfRange(javaEncoded, 1, javaEncoded.length);
			ckInteger = new org.cryptokitty.jni.BigInteger(ckEncoded);
			ceAvailable = jeAvailable = ciAvailable = true;
		}
	}

	/**
	 * 
	 * @return The CryptoKittty encoded integer.
	 */
	public byte[] getCKEncoded() {

		if (!ceAvailable) {
			if (ciAvailable) {
				ckEncoded = ckInteger.getEncoded();
				ceAvailable = true;
			}
			else if (jeAvailable) {
				je2ce();
			}
			else if (jiAvailable) {
				ji2ce();
			}
		}
		return ckEncoded;

	}

	/**
	 * 
	 * @return The CryptoKitty integer.
	 */
	public org.cryptokitty.jni.BigInteger getCKInteger() {

		if (!ciAvailable) {
			if (ceAvailable) {
				ckInteger = new org.cryptokitty.jni.BigInteger(ckEncoded);
				ciAvailable = true;
			}
			else if (jeAvailable) {
				je2ci();
			}
			else if (jiAvailable) {
				ji2ci();
			}
		}
		return ckInteger;

	}

	/**
	 * 
	 * @return The Java integer encoding.
	 */
	public byte[] getJavaEncoded() {

		if (!jeAvailable) {
			if (jiAvailable) {
				javaEncoded = javaInteger.toByteArray();
				jeAvailable = true;
			}
			else if (ceAvailable) {
				ce2je();
			}
			else if (ciAvailable) {
				ci2je();
			}
		}
		return javaEncoded;

	}

	/**
	 * 
	 * @return The Java integer.
	 */
	public java.math.BigInteger getJavaInteger() {

		if (!jiAvailable) {
			if (jeAvailable) {
				javaInteger = new java.math.BigInteger(javaEncoded);
				jiAvailable = true;
			}
			else if (ceAvailable) {
				ce2ji();
			}
			else if (ciAvailable) {
				ci2ji();
			}
		}
		return javaInteger;

	}

}
