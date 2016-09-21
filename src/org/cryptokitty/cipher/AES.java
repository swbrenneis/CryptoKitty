/**
 * 
 */
package org.cryptokitty.cipher;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import org.cryptokitty.exceptions.IllegalBlockSizeException;
import org.cryptokitty.exceptions.InvalidKeyException;

/**
 * @author stevebrenneis
 *
 */
public class AES implements BlockCipher {

	/**
	 * Key size enumerators.
	 */
	public static final int AES128 = 16;
	public static final int AES192 = 24;
	public static final int AES256 = 32;

	/**
	 * Something.
	 */
	private static final int Nb = 4;

	/**
	 * Inverse substitution box.
	 */
	private static final int InvSbox[] = 
		{ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
			0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
			0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
			0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
			0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
			0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
			0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
			0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
			0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
			0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
			0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
			0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
			0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
			0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
			0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

	/**
	 * 
	 */
	static final int Rcon[] =
		{ 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
			0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
			0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
			0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
			0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
			0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
			0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
			0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
			0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
			0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
			0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
			0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
			0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
			0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
			0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
			0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };

	/**
	 * Substitution box
	 */
	static final int Sbox[] = 
		{ 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

	/**
	 * It's unfortunate that Java doesn't have typedefs
	 */
	private static final class Word {
		Word() { word = new int[4]; }
		int[] word;
	}

	/**
	 * Cipher state array.
	 */
	private static final class StateArray {
		StateArray() {
			row0 = new Word();
			row1 = new Word();
			row2 = new Word();
			row3 = new Word();
		}
		@SuppressWarnings("unused")
		StateArray(Word r0, Word r1, Word r2, Word r3) {
			copyWord(row0, r0);
			copyWord(row1, r1);
			copyWord(row2, r2);
			copyWord(row3, r3);
		}
		StateArray(StateArray other) {
			row0 = new Word();
			row1 = new Word();
			row2 = new Word();
			row3 = new Word();
			copyWord(row0, other.row0);
			copyWord(row1, other.row1);
			copyWord(row2, other.row2);
			copyWord(row3, other.row3);
		}
		Word row0;
		Word row1;
		Word row2;
		Word row3;
    }
	
	private static final StateArray cx = new StateArray();
		{ cx.row0.word = new int[] { 2, 3, 1, 1 };
			cx.row1.word = new int[] { 1, 2, 3, 1 };
			cx.row2.word = new int[] { 1, 1, 2, 3 };
			cx.row3.word = new int[] { 3, 1, 1, 2 }; };

	private static final StateArray invax = new StateArray();
		{ invax.row0.word = new int[] { 0x0e, 0x0b, 0x0d, 0x09 };
			invax.row1.word = new int[] { 0x09, 0x0e, 0x0b, 0x0d };
			invax.row2.word = new int[] { 0x0d, 0x09, 0x0e, 0x0b };
			invax.row3.word = new int[] { 0x0b, 0x0d, 0x09, 0x0e }; };

	/**
	 * Key schedule length
	 */
	private long keyScheduleSize;

	/**
	 * Something.
	 */
    private int Nk;

    /**
     * Something.
     */
    private int Nr;

    /**
     * Cipher state.
     */
    private StateArray state;
    
	/**
	 * @throws IllegalBlockSizeException 
	 * 
	 */
	public AES(int keySize) throws InvalidKeyException {

		switch (keySize) {
			case AES128:
				Nk = 4;
				Nr = 10;
				break;
			case AES192:
				Nk = 6;
				Nr = 12;
				break;
			case AES256:
				Nk = 8;
				Nr = 14;
				break;
			default:
				throw new InvalidKeyException("Invalid AES key size");
		}

		keyScheduleSize = Nb * (Nr + 1);
		state = new StateArray();

	}

	/**
	 * Add (xor) the round key state.
	 * 
	 * @param roundKey
	 */
	private void AddRoundKey(final Word[] roundKey) {

		Word column = new Word();
		for (int col = 0; col < 4; ++col) {
			copyWord(column, roundKey[col]);
			state.row0.word[col] = state.row0.word[col] ^ column.word[0];
			state.row1.word[col] = state.row1.word[col] ^ column.word[1];
			state.row2.word[col] = state.row2.word[col] ^ column.word[2];
			state.row3.word[col] = state.row3.word[col] ^ column.word[3];
		}

	}

	/**
	 * 
	 * @param dest
	 * @param src
	 */
	private static void copyWord(Word dest, Word src) {

		dest.word = Arrays.copyOf(src.word, src.word.length);

	}
	
	/**
	 * From FIPS 197
	 *
	 * Nb = 4 for this FIPS
	 * Nr = 10, 12, 14 for 128, 192, 256 bit keys respectively
	 * Nk = Number of 32 bit words in the cipher key. 4, 6, or 8.
	 * 
	 * Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
	 *
	 * begin
	 *
	 *  byte state[4,Nb]
	 *
	 *  state = in
	 *
	 *  AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4
	 *
	 *  for round = 1 step 1 to Nr–1
	 *
	 *      SubBytes(state) // See Sec. 5.1.1
	 *
	 *      ShiftRows(state) // See Sec. 5.1.2
	 *
	 *      MixColumns(state) // See Sec. 5.1.3
	 *
	 *      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
	 *
	 *  end for
	 *
	 *  SubBytes(state)
	 *
	 *  ShiftRows(state)
	 *
	 *  AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
	 *
	 *  out = state
	 *
	 * end
	 * 
	 * @param plaintext
	 * @param keySchedule
	 * @throws BadParameterException 
	 *  
	 */
	private void Cipher(final byte[] plaintext, final Word[] keySchedule) {

	    // Load the state
	    for (int n = 0; n < 4; ++n) {
	        state.row0.word[n] = plaintext[n*4];
	        state.row1.word[n] = plaintext[(n*4)+1];
	        state.row2.word[n] = plaintext[(n*4)+2];
	        state.row3.word[n] = plaintext[(n*4)+3];
	    }

	    Word roundKey[] = new Word[4];
	    for (int n = 0; n < 4; ++n) {
	    	roundKey[n] = new Word();
	        copyWord(roundKey[n], keySchedule[n]);
	    }
	    AddRoundKey(roundKey);

	    // Process rounds
	    for (int round = 1; round < Nr; ++round) {
	        SubBytes();
	        ShiftRows();
	        MixColumns();
	        for (int n = 0; n < 4; ++n) {
	            copyWord(roundKey[n], keySchedule[(round * Nb)+n]);
	        }
	        AddRoundKey(roundKey);
	    }

	    // Finish up.
	    SubBytes();
	    ShiftRows();
	    for (int n = 0; n < 4; ++n) {
	        copyWord(roundKey[n], keySchedule[(Nr*Nb)+n]);
	    }
	    AddRoundKey(roundKey);

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#decrypt(byte[], byte[])
	 */
	@Override
	public byte[] decrypt(byte[] ciphertext, byte[] key) throws IllegalBlockSizeException {

		if (ciphertext.length != Nb * 4) {
	        throw new IllegalBlockSizeException("Illegal AES ciphertext size");
	    }

	    Word keySchedule[] = new Word[(int)keyScheduleSize];
	    for (int i = 0; i < keyScheduleSize; ++i) {
	    	keySchedule[i] = new Word();
	    }
	    KeyExpansion(key, keySchedule);
	    InvCipher(ciphertext, keySchedule);
	    ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
	    for (int col = 0; col < 4; ++col) {
	        plaintext.write(state.row0.word[col]);
	        plaintext.write(state.row1.word[col]);
	        plaintext.write(state.row2.word[col]);
	        plaintext.write(state.row3.word[col]);
	    }

	    return plaintext.toByteArray();

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#encrypt(byte[], byte[])
	 */
	@Override
	public byte[] encrypt(byte[] plaintext, byte[] key) throws IllegalBlockSizeException {

	    if (plaintext.length != Nb * 4) {
	        throw new IllegalBlockSizeException("Illegal AES plaintext size");
	    }

	    Word keySchedule[] = new Word[(int)keyScheduleSize];
	    for (int i = 0; i < keyScheduleSize; ++i) {
	    	keySchedule[i] = new Word();
	    }
	    KeyExpansion(key, keySchedule);
	    Cipher(plaintext, keySchedule);
	    ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
	    for (int col = 0; col < 4; ++col) {
	        ciphertext.write(state.row0.word[col]);
	        ciphertext.write(state.row1.word[col]);
	        ciphertext.write(state.row2.word[col]);
	        ciphertext.write(state.row3.word[col]);
	    }

	    return ciphertext.toByteArray();

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#getBlockSize()
	 */
	@Override
	public int getBlockSize() {

		return 16;

	}

	/**
	 * InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
	 *
	 * begin
	 *
	 *  byte state[4,Nb]
	 *
	 *  state = in
	 *
	 *  AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
	 *
	 *  for round = Nr-1 step -1 downto 1
	 *
	 *      InvShiftRows(state) // See Sec. 5.3.1
	 *
	 *      InvSubBytes(state) // See Sec. 5.3.2
	 *
	 *      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
	 *
	 *      InvMixColumns(state) // See Sec. 5.3.3
	 *
	 *  end for
	 *
	 *  InvShiftRows(state)
	 *
	 *  InvSubBytes(state)
	 *
	 *  AddRoundKey(state, w[0, Nb-1])
	 *
	 *  out = state
	 *
	 * end
	 * 
	 * @param ciphertext
	 * @param keySchedule
	 * @throws IllegalBlockSizeException
	 * @throws IllegalBlockSizeException 
	 */
	private void InvCipher(final byte[] ciphertext, final Word[] keySchedule) throws IllegalBlockSizeException {

	    if (ciphertext.length != Nb * 4) {
	        throw new IllegalBlockSizeException("Invalid AES ciphertext block size.");
	    }

	    // Load the state
	    for (int n = 0; n < 4; ++n) {
	        state.row0.word[n] = ciphertext[n*4];
	        state.row1.word[n] = ciphertext[(n*4)+1];
	        state.row2.word[n] = ciphertext[(n*4)+2];
	        state.row3.word[n] = ciphertext[(n*4)+3];
	    }

	    Word roundKey[] = new Word[4];
	    for (int n = 0; n < 4; ++n) {
	    	roundKey[n] = new Word();
	        copyWord(roundKey[n], keySchedule[(Nr*Nb)+n]);
	    }
	    AddRoundKey(roundKey);

	    for (int round = Nr - 1; round >= 1; --round) {
	        InvShiftRows();
	        InvSubBytes();
	        for (int n = 0; n < 4; ++n) {
	            copyWord(roundKey[n], keySchedule[(round*Nb)+n]);
	        }
	        AddRoundKey(roundKey);
	        InvMixColumns();
	    }

	    InvShiftRows();
	    InvSubBytes();
	    for (int n = 0; n < 4; ++n) {
	        copyWord(roundKey[n], keySchedule[n]);
	    }
	    AddRoundKey(roundKey);

	}

	/**
	 * Matrix multiplication transformation.
	 *
	 * Each column in the state is multiplied and added as
	 * a 4 byte polynomial against the inverse polynomial
	 * function ax. The "multiplication" and "addition" are
	 * as defined in Rijndael finite field operations.
	 */
	private void InvMixColumns() {

	    StateArray m = state;

	    for (int c = 0; c < 4; ++c) {
	        state.row0.word[c] = RijndaelMult(invax.row0.word[0], m.row0.word[c])
	                        ^ RijndaelMult(invax.row0.word[1], m.row1.word[c])
	                        ^ RijndaelMult(invax.row0.word[2], m.row2.word[c])
	                        ^ RijndaelMult(invax.row0.word[3], m.row3.word[c]);
	        state.row1.word[c] = RijndaelMult(invax.row1.word[0], m.row0.word[c])
	                        ^ RijndaelMult(invax.row1.word[1], m.row1.word[c])
	                        ^ RijndaelMult(invax.row1.word[2], m.row2.word[c])
	                        ^ RijndaelMult(invax.row1.word[3], m.row3.word[c]);
	        state.row2.word[c] = RijndaelMult(invax.row2.word[0], m.row0.word[c])
	                        ^ RijndaelMult(invax.row2.word[1], m.row1.word[c])
	                        ^ RijndaelMult(invax.row2.word[2], m.row2.word[c])
	                        ^ RijndaelMult(invax.row2.word[3], m.row3.word[c]);
	        state.row3.word[c] = RijndaelMult(invax.row3.word[0], m.row0.word[c])
	                        ^ RijndaelMult(invax.row3.word[1], m.row1.word[c])
	                        ^ RijndaelMult(invax.row3.word[2], m.row2.word[c])
	                        ^ RijndaelMult(invax.row3.word[3], m.row3.word[c]);
	    }

	}


	/**
	 * Columns are rotated as follows:
	 *      row 0 rotated 0 left.
	 *      row 1 rotated 1 left.
	 *      row 2 rotated 2 left.
	 *      row 3 rotated 3 left.
	 */
	private void InvShiftRows() {

	    rol(1, state.row1);
	    rol(2, state.row2);
	    rol(3, state.row3);
	}

	/**
	 * Perform the inverse S-Box transformation.
	 * For each byte in the state s[r,c] substitute with
	 * the byte at InvSbox[s[r,c]].
	 */
	private void InvSubBytes() {

		for (int col = 0; col < 4; ++col) {
			int index = state.row0.word[col] & 0xff;
			state.row0.word[col] = InvSbox[index];
			index = state.row1.word[col] & 0xff;
			state.row1.word[col] = InvSbox[index];
			index = state.row2.word[col] & 0xff;
			state.row2.word[col] = InvSbox[index];
			index = state.row3.word[col] & 0xff;
			state.row3.word[col] = InvSbox[index];
		}

	}

	/**
	 * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
	 *
	 *  begin
	 *
	 *      word temp
	 *
	 *      i = 0
	 *
	 *      while (i < Nk)
	 *
	 *          w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
	 *
	 *          i = i+1
	 *
	 *      end while
	 *
	 *      i = Nk
	 *
	 *      while (i < Nb * (Nr+1)]
	 *
	 *          temp = w[i-1]
	 *
	 *          if (i mod Nk = 0)
	 *
	 *              temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
	 *
	 *          else if (Nk > 6 and i mod Nk = 4)
	 *
	 *              temp = SubWord(temp)
	 *
	 *          end if
	 *
	 *          w[i] = w[i-Nk] xor temp
	 *
	 *          i = i + 1
	 *
	 *      end while
	 *
	 * end
	 *  
	 * @param key
	 * @param keySchedule
	 */
	private final void KeyExpansion(final byte[] key, Word[] keySchedule) {

		Word temp = new Word();

	    // Copy the key into the key schedule.
	    //keySchedule.copy(0, key, 0);
	    //System.out.println("keySchedule length: " + Integer.toString(keySchedule.length));
	    //System.out.println("Key length: " + Integer.toString(key.length));
	    //System.out.println("Nk: " + Integer.toString(Nk));
	    for (int i = 0; i < Nk; ++i) {
	        for (int n = 0; n < 4; ++n) {
	            keySchedule[i].word[n] = key[(i*4)+n];
	        }
	    }

	    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
	        copyWord(temp, keySchedule[i-1]);
	        if (i % Nk == 0) {
	            // RotWord()
	            int t = temp.word[0];
	            temp.word[0] = temp.word[1];
	            temp.word[1] = temp.word[2];
	            temp.word[2] = temp.word[3];
	            temp.word[3] = t;
	            // SubWord()
	            for (int n = 0; n < 4; ++n) {
	            	// Gosling sucks
	            	int index = temp.word[n] & 0xff;
	                temp.word[n] = Sbox[index];
	            }
	            // xor Rcon
	            temp.word[0] = temp.word[0] ^ Rcon[i / Nk];
	                
	        }
	        else if (Nk > 6 && i % Nk == 4) { // 256 bit keys
	            // SubWord()
	            for (int n = 0; n < 4; ++n) {
	            	int index = temp.word[n] & 0xff;
	                temp.word[n] = Sbox[index];
	            }
	        }
	        Word wink = new Word();
	        copyWord(wink, keySchedule[i-Nk]);
	        for (int n = 0; n < 4; ++n) {
	            wink.word[n] = wink.word[n] ^ temp.word[n];
	        }
	        copyWord(keySchedule[i],wink);
	    }

	}

	/**
	 * Matrix multiplication transformation.
	 *
	 * Each column in the state is multiplied and added as
	 * a 4 byte polynomial against the polynomial function cx.
	 * The "multiplication" and "addition" are as defined in
	 * Rijndael finite field operations.
	 */
	private void MixColumns() {

		StateArray m = new StateArray(state);

		for (int c = 0; c < 4; ++c) {
			state.row0.word[c] = RijndaelMult(cx.row0.word[0], m.row0.word[c])
					^ RijndaelMult(cx.row0.word[1], m.row1.word[c])
					^ RijndaelMult(cx.row0.word[2], m.row2.word[c])
					^ RijndaelMult(cx.row0.word[3], m.row3.word[c]);
			state.row1.word[c] = RijndaelMult(cx.row1.word[0], m.row0.word[c])
					^ RijndaelMult(cx.row1.word[1], m.row1.word[c])
					^ RijndaelMult(cx.row1.word[2], m.row2.word[c])
					^ RijndaelMult(cx.row1.word[3], m.row3.word[c]);
			state.row2.word[c] = RijndaelMult(cx.row2.word[0], m.row0.word[c])
					^ RijndaelMult(cx.row2.word[1], m.row1.word[c])
					^ RijndaelMult(cx.row2.word[2], m.row2.word[c])
					^ RijndaelMult(cx.row2.word[3], m.row3.word[c]);
			state.row3.word[c] = RijndaelMult(cx.row3.word[0], m.row0.word[c])
					^ RijndaelMult(cx.row3.word[1], m.row1.word[c])
					^ RijndaelMult(cx.row3.word[2], m.row2.word[c])
					^ RijndaelMult(cx.row3.word[3], m.row3.word[c]);
		}

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.cipher.BlockCipher#reset()
	 */
	@Override
	public void reset() {

		state = new StateArray();

	}

	/**
	 * Run the following loop eight times (once per bit).
	 * It is OK to stop when a or b are zero before an iteration:
	 * 1. If the rightmost bit of b is set, exclusive OR the product
	 *    by the value of a. This is polynomial addition.
	 * 2. Shift b one bit to the right, discarding the rightmost bit,
	 *    and making the leftmost bit have a value of zero. This divides
	 *    the polynomial by x, discarding the x0 term.
	 * 3. Keep track of whether the leftmost bit of a is set to one
	 *    and call this value carry.
	 * 4. Shift a one bit to the left, discarding the leftmost bit,
	 *    and making the new rightmost bit zero. This multiplies the
	 *    polynomial by x, but we still need to take account of carry
	 *    which represented the coefficient of x7.
	 * 5. If carry had a value of one, exclusive or a with the
	 *    hexadecimal number 0x1b (00011011 in binary). 0x1b corresponds
	 *    to the irreducible polynomial with the high term eliminated.
	 *    Conceptually, the high term of the irreducible polynomial and
	 *    carry add modulo 2 to 0.
	 *
	 * @param lhs
	 * @param rhs
	 * @return
	 */
	private final int RijndaelMult(int lhs, int rhs) {

		if (lhs == 0 || rhs == 0) {
			return 0;
		}

		if (lhs == 1) {
			return rhs;
		}

		if (rhs == 1) {
			return lhs;
		}

		int a = lhs;
		int b = rhs;
		int product = 0;
		int carry;
		for (int l = 0; l < 8 && a > 0 && b > 0; ++l) {
			if ((b & 1) != 0) {
				product = product ^ a;
			}
			carry = a & 0x80;
			a = (a << 1) & 0xff;
			if (carry != 0) {
				a = a ^ 0x1b;
			}
			b = (b >> 1) & 0xff; 
		}
		return product;

	}

	/**
	 * Rotate a word left.
	 * 
	 * @param count
	 * @param a
	 */
    private final void rol(int count, Word a) {

    	int tmp;
        for (int n = 0; n < count; ++n) {
            tmp = a.word[3];
            a.word[3] = a.word[2];
            a.word[2] = a.word[1];
            a.word[1] = a.word[0];
            a.word[0] = tmp;
        }
    }

    /**
	 * Rotate a Word right
     * 
     * @param count
     * @param a
     */
	private final void ror(int count, Word a) {
        int tmp;
        for (int n = 0; n < count; ++n) {
            tmp = a.word[0];
            a.word[0] = a.word[1];
            a.word[1] = a.word[2];
            a.word[2] = a.word[3];
            a.word[3] = tmp;
        }
    }

	/**
	 * Columns are rotated as follows:
	 *      row 0 rotated 0 right.
	 *      row 1 rotated 1 right.
	 *      row 2 rotated 2 right.
	 *      row 3 rotated 3 right.
	 */
	void ShiftRows() {

	    ror(1, state.row1);
	    ror(2, state.row2);
	    ror(3, state.row3);

	}


	/**
	 * Perform the S-Box transformation.
	 * For each byte in the state s[r,c] substitute with
	 * the byte at Sbox[s[r,c]].
	 */
	private void SubBytes() {

		for (int col = 0; col < 4; ++col) {
			// Gosling really, really sucks.
			int index = state.row0.word[col] & 0xff;
			state.row0.word[col] = Sbox[index];
			index = state.row1.word[col] & 0xff;
			state.row1.word[col] = Sbox[index];
			index = state.row2.word[col] & 0xff;
			state.row2.word[col] = Sbox[index];
			index = state.row3.word[col] & 0xff;
			state.row3.word[col] = Sbox[index];
		}

	}

}
