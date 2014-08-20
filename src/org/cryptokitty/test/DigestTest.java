/**
 * 
 */
package org.cryptokitty.test;

import java.util.Arrays;

import org.cryptokitty.provider.digest.CKSHA256;
import org.cryptokitty.provider.digest.CKSHA512;
import org.cryptokitty.provider.digest.CKSHA384;

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

		byte[] message1 = 
			{ 0x61, 0x62, 0x63 };

		byte[] answer1 =
			{ (byte)0xba, 0x78, 0x16, (byte)0xbf, (byte)0x8f, 0x01, (byte)0xcf, (byte)0xea,
				0x41, 0x41, 0x40, (byte)0xde, 0x5d, (byte)0xae, 0x22, 0x23,
				(byte)0xb0, 0x03, 0x61, (byte)0xa3, (byte)0x96, 0x17, 0x7a, (byte)0x9c,
				(byte)0xb4, 0x10, (byte)0xff, 0x61, (byte)0xf2, 0x00, 0x15, (byte)0xad };
		
		byte[] answer2 =
			{ (byte)0xdd, (byte)0xaf, 0x35, (byte)0xa1, (byte)0x93, 0x61, 0x7a, (byte)0xba,
				(byte)0xcc, 0x41, 0x73, 0x49, (byte)0xae, 0x20, 0x41, 0x31,
				0x12, (byte)0xe6, (byte)0xfa, 0x4e, (byte)0x89, (byte)0xa9, 0x7e, (byte)0xa2,
				0x0a, (byte)0x9e, (byte)0xee, (byte)0xe6, 0x4b, 0x55, (byte)0xd3, (byte)0x9a,
				0x21, (byte)0x92, (byte)0x99, 0x2a, 0x27, 0x4f, (byte)0xc1, (byte)0xa8,
				0x36, (byte)0xba, 0x3c, 0x23, (byte)0xa3, (byte)0xfe, (byte)0xeb, (byte)0xbd,
				0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, (byte)0xe8, 0x0e,
				0x2a, (byte)0x9a, (byte)0xc9, 0x4f, (byte)0xa5, 0x4c, (byte)0xa4, (byte)0x9f };

		byte[] answer3 = 
			{ (byte)0xcb, 0x00, 0x75, 0x3f, 0x45, (byte)0xa3, 0x5e, (byte)0x8b, (byte)0xb5,
				(byte)0xa0, 0x3d, 0x69, (byte)0x9a, (byte)0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32,
				(byte)0xab, 0x0e, (byte)0xde, (byte)0xd1, 0x63, 0x1a, (byte)0x8b, 0x60, 0x5a,
				0x43, (byte)0xff, 0x5b, (byte)0xed, (byte)0x80, (byte)0x86, 0x07, 0x2b,
				(byte)0xa1, (byte)0xe7, (byte)0xcc, 0x23, 0x58, (byte)0xba, (byte)0xec,
				(byte)0xa1, 0x34, (byte)0xc8, 0x25, (byte)0xa7 };
	
		CKSHA256 sha256 = new CKSHA256();
		byte[] digest1 = sha256.digest(message1);
		if (Arrays.equals(digest1, answer1)) {
			System.out.println("Message digest test 1 passed!");
		}
		else {
			System.out.println("Message digest test 1 failed!");
		}

		CKSHA512 sha512 = new CKSHA512();
		byte[] digest2 = sha512.digest(message1);
		if (Arrays.equals(digest2, answer2)) {
			System.out.println("Message digest test 2 passed!");
		}
		else {
			System.out.println("Message digest test 2 failed!");
		}

		CKSHA384 sha384 = new CKSHA384();
		byte[] digest3 = sha384.digest(message1);
		if (Arrays.equals(digest3, answer3)) {
			System.out.println("Message digest test 3 passed!");
		}
		else {
			System.out.println("Message digest test 3 failed!");
		}

	}

}
