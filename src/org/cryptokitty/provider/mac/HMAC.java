/**
 * 
 */
package org.cryptokitty.provider.mac;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.cryptokitty.provider.BadParameterException;
import org.cryptokitty.provider.digest.Digest;

/**
 * @author stevebrenneis
 *
 */
public class HMAC {

	/**
	 * Digest block size.
	 */
	private long B;
	
	/**
	 * Digest length
	 */
	private long L;

	/**
	 * HMAC key.
	 */
	private byte[] K;

	/**
	 * Message digest.
	 */
	private Digest digest;

	/**
	 * 
	 * @param digest
	 */
	public HMAC(Digest digest) {

		this.digest = digest;
		B = digest.getBlockSize();
		L = digest.getDigestLength();

	}

	/**
	 * 
	 * @param hmac
	 * @return
	 */
	boolean authenticate(byte[] hmac) {

		return false;
	    //return getHMAC() == hmac;

	}

	/*
	 * Generate an HMAC key. The key size will be rounded
	 * to a byte boundary. The Key must be at least L bytes.
	 */
	public byte[] generateKey(int bitsize) throws BadParameterException {

	    if (bitsize / 8 < L) {
	        throw new BadParameterException("Invalid key size");
	    }

	    // TODO Implement Fortuna
	    //FortunaSecureRandom secure;
	    SecureRandom secure;
		try {
			secure = SecureRandom.getInstanceStrong();
		    K = new byte[bitsize / 8];
		    secure.nextBytes(K);
		    return K;
		}
		catch (NoSuchAlgorithmException e) {
			// Sure hope not.
		}
		
		return null;

	}

	/**
	 * 
	 * @return
	 */
	public long getDigestLength() {
		
		return digest.getDigestLength();

	}

	/**
	 * Generate the HMAC.
	 *
	 * H(K XOR opad, H(K XOR ipad, text))
	 *
	 *
	coder::ByteArray HMAC::getHMAC() {

	    if (K.getLength() == 0) {
	        throw IllegalStateException("Key not set");
	    }

	    // Pad or truncate the key until it is B bytes.
	    coder::ByteArray k;
	    if (K.getLength() > B) {
	        k = hash->digest(K);
	    }
	    else {
	        k = K;
	    }
	    coder::ByteArray pad(B - k.getLength());
	    k.append(pad);
	    hash->reset();

	    // First mask.
	    coder::ByteArray i(k ^ ipad);
	    i.append(text);
	    coder::ByteArray h1(hash->digest(i));
	    hash->reset();
	    coder::ByteArray o(k ^ opad);
	    o.append(h1);}
    return hash->digest(o);

}*/

}
