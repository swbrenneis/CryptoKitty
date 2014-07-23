/**
 * 
 */
package org.cryptokitty.data;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author Steve Brenneis
 *
 * Multi-precision Integer. Similar to Java's BigInteger, but it
 * is bit based instead of byte based. See RFC 4880, section 3.2
 */
public class MPI {

	/*
	 * Bit precision of the MPI. According to the RFC, this is a
	 * 16 bit, unsigned quantity, so it is held here in an integer.
	 */
	private Scalar16 precision;

	/*
	 * The MPI value. Represents a big endian number, precision bits
	 * in length.
	 */
	private byte[] value;

	/**
	 * Creates an MPI from an input stream.
	 */
	public MPI(InputStream in) throws DataException {

		precision = new Scalar16(in);

		int mpiLength = (precision.getValue() + 7) / 8;
		value = new byte[mpiLength];
		try {
			in.read(value);
		}
		catch (IOException e) {
			new DataException(e);
		}

	}

	/**
	 * Takes a precision value and a byte array value. Assumes that the
	 * array is correctly formatted.
	 */
	public MPI(int precision, byte[] value) {
		this.precision = new Scalar16(precision);
		this.value = value;
	}

	/**
	 * Takes a raw byte array value (no precision octets). Calculates
	 * precision and reformats the array.
	 */
	public MPI(byte[] value) {
		// Strip leading zeros.
		int index = 0;
		while (index < value.length && value[index] == 0) {
			index++;
		}
		this.value = Arrays.copyOfRange(value, index, value.length);
		
		// Calculate the precision.
		int p = (this.value.length - 1) * 8;
		int modbits = 8;
		int test = this.value[0];
		while ((test & 0x80) == 0) {
			test = (test << 1) & 0xff;
			modbits--;
		}
		p += modbits;
		precision = new Scalar16(p);

	}

	/*
	 * Create an encoded octet array representing the integer.
	 */
	public byte[] getEncoded() {
		// Sadly, we have to do this the hard way.
		byte[] encoded = new byte[value.length + 2];
		for (int i = 0; i < value.length; ++i) {
			encoded[i+2] = value[i];
		}
		byte[] pb = precision.getEncoded();
		encoded[0] = pb[0];
		encoded[1] = pb[1];
		return encoded;
	}

	/*
	 * Returns the integer as a Java BigInteger.
	 */
	public BigInteger toBigInteger() {
		return new BigInteger(value);
	}

}
