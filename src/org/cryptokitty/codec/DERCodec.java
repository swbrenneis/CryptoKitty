/**
 * 
 */
package org.cryptokitty.codec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.cryptokitty.exceptions.CodecException;

/**
 * @author stevebrenneis
 *
 */
public class DERCodec {

	/**
	 * DER tags.
	 */
	private static final byte INTEGER_TAG = 0x02;
	private static final byte NULL_TAG = 0x05;
	private static final byte BIT_STRING_TAG = 0x03;
	private static final byte OCTET_STRING_TAG = 0x04;
	private static final byte OID_TAG = 0x06;
	private static final byte SEQUENCE_TAG = 0x30;

	/**
	 * DER constants
	 */
	static final byte DER_NULL[] = { 0x05, 0x00 };
	static final byte RSA_OID[] = { 0x06, 0x09, 0x2A, (byte)0x86, 0x48,
									(byte)0x86, (byte)0xF7, 0x0D, 0x01,
									0x01, 0x01 };

	/**
	 * 
	 */
	public DERCodec() {
		// TODO Auto-generated finalructor stub
	}

	/**
	 * 
	 * @param out
	 * @param keyType
	 */
	public void encodeAlgorithm(ByteArrayOutputStream out) {

		ByteArrayOutputStream algorithm = new ByteArrayOutputStream();
		try {
			algorithm.write(RSA_OID);
			algorithm.write(DER_NULL);
		}
		catch (IOException e) {
			// Nope.
		}
		encodeSequence(out, algorithm.toByteArray());

	}

	/**
	 * 
	 * @param out
	 * @param bits
	 */
	public void encodeBitString(ByteArrayOutputStream out, byte[] bits) {

		out.write(BIT_STRING_TAG);
		setLength(out, bits.length + 1);
		try {
			out.write(0);
			out.write(bits);
		}
		catch (IOException e) {
			// Not happening
		}

	}

	/**
	 * 
	 * @param out
	 * @param integer
	 */
	public void encodeInteger(ByteArrayOutputStream out, byte[] integer) {

		out.write(INTEGER_TAG);
		setLength(out, integer.length);
		try {
			out.write(integer);
		}
		catch (IOException e) {
			// Not happening
		}

	}

	/**
	 * 
	 * @param out
	 * @param octets
	 */
	public void encodeOctetString(ByteArrayOutputStream out, byte[] octets) {

		out.write(OCTET_STRING_TAG);
		setLength(out, octets.length);
		try {
			out.write(octets);
		}
		catch (IOException e) {
			// Not happening
		}

	}

	/**
	 * 
	 * @param out
	 * @param integer
	 */
	public void encodeSequence(ByteArrayOutputStream out, byte[] sequence) {

		out.write(SEQUENCE_TAG);
		setLength(out, sequence.length);
		try {
			out.write(sequence);
		}
		catch (IOException e) {
			// Not happening
		}

	}

	/**
	 * 
	 * @param source
	 * @param bitstring
	 * @throws CodecException
	 */
	public void getBitString(ByteArrayInputStream source, ByteArrayOutputStream bitstring)
																	throws CodecException {

		if (source.read() != BIT_STRING_TAG) {
			throw new CodecException("Not a bit string");
		}

		getSegment(source, bitstring);

	}

	/**
	 * 
	 * @param source
	 * @param sequence
	 * @throws CodecException
	 */
	public void getInteger(ByteArrayInputStream source, ByteArrayOutputStream integer)
																	throws CodecException {

		if (source.read() != INTEGER_TAG) {
			throw new CodecException("Not an integer");
		}

		getSegment(source, integer);

	}

	/**
	 * 
	 * @param source
	 * @param octetstring
	 * @throws CodecException
	 */
	public void getOctetString(ByteArrayInputStream source, ByteArrayOutputStream octetstring)
																	throws CodecException {

		if (source.read() != OCTET_STRING_TAG) {
			throw new CodecException("Not an octet string");
		}

		getSegment(source, octetstring);

	}

	/**
	 * 
	 * @param source
	 * @param segment
	 * @throws CodecException
	 */
	public void getSegment(ByteArrayInputStream source, ByteArrayOutputStream segment)
																throws CodecException {

		// The first byte is the tag.
		// BER/DER length encoding:
		// If MSB of first byte is not set, segment length is the first byte/
		// It MSB is set, lower 7 bits constant number of bytes containing the length.
		// Length is always expressed in the minimum number of bytes.
		try {
			int length = 0;
			int indicator = source.read();
			if ((indicator & 0x80) != 0) {
				int lengthSize = indicator & 0x7f;
				byte[] lBytes = new byte[lengthSize];
				source.read(lBytes);
				if (lengthSize == 2) {
					Scalar16 s16 = new Scalar16(lBytes);
					length = s16.getValue();
				}
				else {
					Scalar32 s32 = new Scalar32(lBytes);
					length = s32.getValue();
				}
			}
			else {
				length = indicator;
			}
			// Read the segment.
			byte[] segBytes = new byte[length];
			source.read(segBytes);
			segment.write(segBytes);
		}
		catch (IOException e) {
			throw new CodecException("Invalid segment");
		}

	}

	/**
	 * Get an ASN.1 sequence.
	 * 
	 * @param source
	 * @param sequence
	 * @return
	 * @throws CodecException
	 */
	public void getSequence(ByteArrayInputStream source, ByteArrayOutputStream sequence)
													throws CodecException {

		if (source.read() != SEQUENCE_TAG) {
			throw new CodecException("Not a sequence");
		}
		
		getSegment(source, sequence);

	}

	/**
	 * Parses the key algorithm sequence. There isn't anything useful here at the moment.
	 * @param source
	 * @throws CodecException 
	 */
	public void parseAlgorithm(ByteArrayInputStream source) throws CodecException {

		ByteArrayOutputStream sequence = new ByteArrayOutputStream();
		getSequence(source, sequence);
		ByteArrayInputStream algorithm = new ByteArrayInputStream(sequence.toByteArray());

		if (algorithm.read() != OID_TAG) {
			throw new CodecException("Not a sequence");
		}

		ByteArrayOutputStream oid = new ByteArrayOutputStream();
		getSegment(algorithm, oid);
		byte[] rsa_oid = Arrays.copyOfRange(RSA_OID, 2, RSA_OID.length);
		if (!Arrays.equals(oid.toByteArray(), rsa_oid)) {
			throw new CodecException("Invalid RSA object ID");
		}
		if (algorithm.available() == 0) {
			throw new CodecException("Invalid algorithm encoding");
		}

		int nullTag = algorithm.read();
		int nullValue = algorithm.read();
		if (algorithm.available() != 0 || nullTag != NULL_TAG || nullValue != 0) {
			throw new CodecException("Invalid algorithm encoding");
		}

	}

	/**
	 * 
	 * @param out
	 * @param length
	 */
	private void setLength(ByteArrayOutputStream out, int length) {

		try {
			if (length < 128) {
				out.write(length);
			}
			else {
				// A key length of 65,536 bytes would be 524,288 bits.
				// I'll change the code when we get there.
				out.write(0x82);
				Scalar16 s16 = new Scalar16((short)length);
				out.write(s16.getEncoded());
			}
		}
		catch (IOException e) {
			// Nope
		}
	}

}
