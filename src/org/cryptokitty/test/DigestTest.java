/**
 * 
 */
package org.cryptokitty.test;

import java.util.Arrays;

import org.cryptokitty.digest.MD5;
import org.cryptokitty.digest.SHA1;
import org.cryptokitty.digest.SHA224;
import org.cryptokitty.digest.SHA256;
import org.cryptokitty.digest.SHA384;
import org.cryptokitty.digest.SHA512;
import org.cryptokitty.xprovider.digest.CKRIPEMD160;

/**
 * @author stevebrenneis
 *
 */
public class DigestTest {

	/**
	 * 
	 */
	public DigestTest() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		byte[] abcMessage = "abc".getBytes();
		
		byte[] paddingMessage =
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();

		byte[] emptyAnswerSHA256 = 
			{ (byte)0xe3, (byte)0xb0, (byte)0xc4, 0x42, (byte)0x98, (byte)0xfc, 0x1c, 0x14,
				(byte)0x9a, (byte)0xfb, (byte)0xf4, (byte)0xc8, (byte)0x99, 0x6f, (byte)0xb9,
				0x24, 0x27, (byte)0xae, 0x41, (byte)0xe4, 0x64, (byte)0x9b, (byte)0x93, 0x4c,
				(byte)0xa4, (byte)0x95, (byte)0x99, 0x1b, 0x78, 0x52, (byte)0xb8, 0x55 };

		byte[] abcAnswerSHA256 =
			{ (byte)0xba, 0x78, 0x16, (byte)0xbf, (byte)0x8f, 0x01, (byte)0xcf, (byte)0xea,
				0x41, 0x41, 0x40, (byte)0xde, 0x5d, (byte)0xae, 0x22, 0x23,
				(byte)0xb0, 0x03, 0x61, (byte)0xa3, (byte)0x96, 0x17, 0x7a, (byte)0x9c,
				(byte)0xb4, 0x10, (byte)0xff, 0x61, (byte)0xf2, 0x00, 0x15, (byte)0xad };

		byte[] paddingAnswerSHA256 =
			{ 0x24, (byte)0x8d, 0x6a, 0x61, (byte)0xd2, 0x06, 0x38, (byte)0xb8, (byte)0xe5,
				(byte)0xc0, 0x26, (byte)0x93, 0x0c, 0x3e, 0x60, 0x39, (byte)0xa3, 0x3c,
				(byte)0xe4, 0x59, 0x64, (byte)0xff, 0x21, 0x67, (byte)0xf6, (byte)0xec,
				(byte)0xed, (byte)0xd4, 0x19, (byte)0xdb, 0x06, (byte)0xc1 };

		byte[] millionAnswerSHA256 =
            { (byte)0xcd, (byte)0xc7, 0x6e, 0x5c, (byte)0x99, 0x14, (byte)0xfb, (byte)0x92,
				(byte)0x81, (byte)0xa1, (byte)0xc7, (byte)0xe2, (byte)0x84, (byte)0xd7,
				0x3e, 0x67, (byte)0xf1, (byte)0x80, (byte)0x9a, 0x48, (byte)0xa4, (byte)0x97,
				0x20, 0x0e, 0x04, 0x6d, 0x39, (byte)0xcc, (byte)0xc7, 0x11, 0x2c, (byte)0xd0 };

		byte[] emptyAnswerSHA512 =
			{ (byte)0xcf, (byte)0x83, (byte)0xe1, 0x35, 0x7e, (byte)0xef, (byte)0xb8,
				(byte)0xbd, (byte)0xf1, 0x54, 0x28, 0x50, (byte)0xd6, 0x6d, (byte)0x80,
				0x07, (byte)0xd6, 0x20, (byte)0xe4, 0x05, 0x0b, 0x57, 0x15, (byte)0xdc,
				(byte)0x83, (byte)0xf4, (byte)0xa9, 0x21, (byte)0xd3, 0x6c, (byte)0xe9,
				(byte)0xce, 0x47, (byte)0xd0, (byte)0xd1, 0x3c, 0x5d, (byte)0x85, (byte)0xf2,
				(byte)0xb0, (byte)0xff, (byte)0x83, 0x18, (byte)0xd2, (byte)0x87, 0x7e,
				(byte)0xec, 0x2f, 0x63, (byte)0xb9, 0x31, (byte)0xbd, 0x47, 0x41, 0x7a,
				(byte)0x81, (byte)0xa5, 0x38, 0x32, 0x7a, (byte)0xf9, 0x27, (byte)0xda, 0x3e };

		byte[] abcAnswerSHA512 =
			{ (byte)0xdd, (byte)0xaf, 0x35, (byte)0xa1, (byte)0x93, 0x61, 0x7a, (byte)0xba,
				(byte)0xcc, 0x41, 0x73, 0x49, (byte)0xae, 0x20, 0x41, 0x31,
				0x12, (byte)0xe6, (byte)0xfa, 0x4e, (byte)0x89, (byte)0xa9, 0x7e, (byte)0xa2,
				0x0a, (byte)0x9e, (byte)0xee, (byte)0xe6, 0x4b, 0x55, (byte)0xd3, (byte)0x9a,
				0x21, (byte)0x92, (byte)0x99, 0x2a, 0x27, 0x4f, (byte)0xc1, (byte)0xa8,
				0x36, (byte)0xba, 0x3c, 0x23, (byte)0xa3, (byte)0xfe, (byte)0xeb, (byte)0xbd,
				0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, (byte)0xe8, 0x0e,
				0x2a, (byte)0x9a, (byte)0xc9, 0x4f, (byte)0xa5, 0x4c, (byte)0xa4, (byte)0x9f };

		byte[] abcAnswerSHA384 = 
			{ (byte)0xcb, 0x00, 0x75, 0x3f, 0x45, (byte)0xa3, 0x5e, (byte)0x8b, (byte)0xb5,
				(byte)0xa0, 0x3d, 0x69, (byte)0x9a, (byte)0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32,
				(byte)0xab, 0x0e, (byte)0xde, (byte)0xd1, 0x63, 0x1a, (byte)0x8b, 0x60, 0x5a,
				0x43, (byte)0xff, 0x5b, (byte)0xed, (byte)0x80, (byte)0x86, 0x07, 0x2b,
				(byte)0xa1, (byte)0xe7, (byte)0xcc, 0x23, 0x58, (byte)0xba, (byte)0xec,
				(byte)0xa1, 0x34, (byte)0xc8, 0x25, (byte)0xa7 };

		byte[] emptyAnswerSHA384 =
			{ 0x38, (byte)0xb0, 0x60, (byte)0xa7, 0x51, (byte)0xac, (byte)0x96, 0x38, 0x4c,
				(byte)0xd9, 0x32, 0x7e, (byte)0xb1, (byte)0xb1, (byte)0xe3, 0x6a, 0x21,
				(byte)0xfd, (byte)0xb7, 0x11, 0x14, (byte)0xbe, 0x07, 0x43, 0x4c, 0x0c,
				(byte)0xc7, (byte)0xbf, 0x63, (byte)0xf6, (byte)0xe1, (byte)0xda, 0x27, 0x4e,
				(byte)0xde, (byte)0xbf, (byte)0xe7, 0x6f, 0x65, (byte)0xfb, (byte)0xd5, 0x1a,
				(byte)0xd2, (byte)0xf1, 0x48, (byte)0x98, (byte)0xb9, 0x5b };

		byte[] emptyAnswerSHA1 =
			{ (byte)0xda, 0x39, (byte)0xa3, (byte)0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
				(byte)0xbf, (byte)0xef, (byte)0x95, 0x60, 0x18, (byte)0x90, (byte)0xaf,
				(byte)0xd8, 0x07, 0x09 };

		byte[] abcAnswerSHA1 = 
			{ (byte)0xa9, (byte)0x99, 0x3e, 0x36, 0x47, 0x06, (byte)0x81, 0x6a, (byte)0xba, 0x3e,
				0x25, 0x71, 0x78, 0x50, (byte)0xc2, 0x6c, (byte)0x9c, (byte)0xd0, (byte)0xd8,
				(byte)0x9d };
	
		byte[] abcAnswerSHA224 = 
			{ 0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, (byte)0xd8, 0x22, (byte)0x86, 0x42, (byte)0xa4,
				0x77, (byte)0xbd, (byte)0xa2, 0x55, (byte)0xb3, 0x2a, (byte)0xad, (byte)0xbc,
				(byte)0xe4, (byte)0xbd, (byte)0xa0, (byte)0xb3, (byte)0xf7, (byte)0xe3, 0x6c,
				(byte)0x9d, (byte)0xa7 };

		byte[] emptyAnswerSHA224 =
			{ (byte)0xd1, 0x4a, 0x02, (byte)0x8c, 0x2a, 0x3a, 0x2b, (byte)0xc9, 0x47, 0x61, 0x02,
				(byte)0xbb, 0x28, (byte)0x82, 0x34, (byte)0xc4, 0x15, (byte)0xa2, (byte)0xb0, 0x1f,
				(byte)0x82, (byte)0x8e, (byte)0xa6, 0x2a, (byte)0xc5, (byte)0xb3, (byte)0xe4, 0x2f };

		byte[] abcAnswerMD5 =
			{ (byte)0x90, 0x01, 0x50, (byte)0x98, 0x3c, (byte)0xd2, 0x4f, (byte)0xb0, (byte)0xd6,
				(byte)0x96, 0x3f, 0x7d, 0x28, (byte)0xe1, 0x7f, 0x72 };

		byte[] emptyAnswerMD5 =
			{ (byte)0xd4, 0x1d, (byte)0x8c, (byte)0xd9, (byte)0x8f, 0x00, (byte)0xb2, 0x04,
				(byte)0xe9, (byte)0x80, 0x09, (byte)0x98, (byte)0xec, (byte)0xf8, 0x42, 0x7e };

		byte[] abcAnswerRIPEMD160 = 
			{ (byte)0x8e, (byte)0xb2, 0x08, (byte)0xf7, (byte)0xe0, 0x5d, (byte)0x98, 0x7a, (byte)0x9b,
				0x04, 0x4a, (byte)0x8e, (byte)0x98, (byte)0xc6, (byte)0xb0, (byte)0x87, (byte)0xf1,
				0x5a, 0x0b, (byte)0xfc };
		
		byte[] emptyAnswerRIPEMD160 =
			{ (byte)0x9c, 0x11, (byte)0x85, (byte)0xa5, (byte)0xc5, (byte)0xe9, (byte)0xfc, 0x54,
				0x61, 0x28, 0x08, (byte)0x97, 0x7e, (byte)0xe8, (byte)0xf5, 0x48, (byte)0xb2, 0x25,
				(byte)0x8d, 0x31 };

		SHA256 sha256 = new SHA256();
		byte[] digestSHA256 = sha256.digest("".getBytes());
		if (Arrays.equals(digestSHA256, emptyAnswerSHA256)) {
			System.out.println("SHA256 empty message test passed!");
		}
		else {
			System.out.println("SHA256 empty message test failed!");
		}

		digestSHA256 = sha256.digest(abcMessage);
		if (Arrays.equals(digestSHA256, abcAnswerSHA256)) {
			System.out.println("SHA256 'abc' test passed!");
		}
		else {
			System.out.println("SHA256 'abc' test failed!");
		}

		digestSHA256 = sha256.digest(paddingMessage);
		if (Arrays.equals(digestSHA256, paddingAnswerSHA256)) {
			System.out.println("SHA256 padding test passed!");
		}
		else {
			System.out.println("SHA256 padding test failed!");
		}

		for (int n = 0; n < 1000000; ++n) {
			sha256.update((byte)'a');
		}
		digestSHA256 = sha256.digest();
		if (Arrays.equals(digestSHA256, millionAnswerSHA256)) {
			System.out.println("SHA256 million test passed!");
		}
		else {
			System.out.println("SHA256 million test failed!");
		}

		SHA512 sha512 = new SHA512();
		byte[] digestSHA512 = sha512.digest("".getBytes());
		if (Arrays.equals(digestSHA512, emptyAnswerSHA512)) {
			System.out.println("SHA512 empty message test passed!");
		}
		else {
			System.out.println("SHA512 empty message test failed!");
		}

		digestSHA512 = sha512.digest(abcMessage);
		if (Arrays.equals(digestSHA512, abcAnswerSHA512)) {
			System.out.println("SHA512 'abc' test passed!");
		}
		else {
			System.out.println("SHA512 'abc' test failed!");
		}

		SHA384 sha384 = new SHA384();
		byte[] digestSHA384 = sha384.digest("".getBytes());
		if (Arrays.equals(digestSHA384, emptyAnswerSHA384)) {
			System.out.println("SHA384 empty message test passed!");
		}
		else {
			System.out.println("SHA384 empty message test failed!");
		}

		digestSHA384 = sha384.digest(abcMessage);
		if (Arrays.equals(digestSHA384, abcAnswerSHA384)) {
			System.out.println("SHA384 'abc' test passed!");
		}
		else {
			System.out.println("SHA384 'abc' test failed!");
		}

		SHA1 sha1 = new SHA1();
		byte[] digestSHA1 = sha1.digest("".getBytes());
		if (Arrays.equals(digestSHA1, emptyAnswerSHA1)) {
			System.out.println("SHA-1 empty message test passed!");
		}
		else {
			System.out.println("SHA-1 empty message test failed!");
		}

		digestSHA1 = sha1.digest(abcMessage);
		if (Arrays.equals(digestSHA1, abcAnswerSHA1)) {
			System.out.println("SHA-1 'abc' test passed!");
		}
		else {
			System.out.println("SHA-1 'abc' test failed!");
		}

		SHA224 sha224 = new SHA224();
		byte[] digestSHA224 = sha224.digest("".getBytes());
		if (Arrays.equals(digestSHA224, emptyAnswerSHA224)) {
			System.out.println("SHA224 empty message test passed!");
		}
		else {
			System.out.println("SHA224 empty message test failed!");
		}

		digestSHA224 = sha224.digest(abcMessage);
		if (Arrays.equals(digestSHA224, abcAnswerSHA224)) {
			System.out.println("SHA224 'abc' test passed!");
		}
		else {
			System.out.println("SHA224 'abc' test failed!");
		}

		MD5 md5 = new MD5();
		byte[] digestMD5 = md5.digest("".getBytes());
		if (Arrays.equals(digestMD5, emptyAnswerMD5)) {
			System.out.println("MD5 empty message test passed!");
		}
		else {
			System.out.println("MD5 empty message test failed!");
		}

		digestMD5 = md5.digest(abcMessage);
		if (Arrays.equals(digestMD5, abcAnswerMD5)) {
			System.out.println("MD5 'abc' test passed!");
		}
		else {
			System.out.println("MD5 'abc' test failed!");
		}

		CKRIPEMD160 ripemd160 = new CKRIPEMD160();
		byte[] digestRIPEMD160 = ripemd160.digest("".getBytes());
		if (Arrays.equals(digestRIPEMD160, emptyAnswerRIPEMD160)) {
			System.out.println("RIPEMD160 empty message test passed!");
		}
		else {
			System.out.println("RIPEMD160 empty message test failed!");
		}

		digestRIPEMD160 = ripemd160.digest(abcMessage);
		if (Arrays.equals(digestRIPEMD160, abcAnswerRIPEMD160)) {
			System.out.println("RIPEMD160 'abc' test passed!");
		}
		else {
			System.out.println("RIPEMD160 'abc' test failed!");
		}

	}

}
