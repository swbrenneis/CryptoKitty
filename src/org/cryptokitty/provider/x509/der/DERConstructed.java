/**
 * 
 */
package org.cryptokitty.provider.x509.der;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import org.cryptokitty.provider.EncodingException;

/**
 * @author Steve Brenneis
 *
 */
public abstract class DERConstructed implements DERType {

	/*
	 * Ordered list of constructed objects.
	 */
	protected ArrayList<DERType> objects;

	/**
	 * Decode constructor.
	 */
	public DERConstructed() {
		this.objects = new ArrayList<DERType>();
	}

	/**
	 * Encode constructor.
	 */
	public DERConstructed(Collection<DERType> object) {
		this.objects = new ArrayList<DERType>();
		this.objects.addAll(objects);
	}

	/*
	 * Add a single DERType
	 */
	public void add(DERType object) {
		this.objects.add(object);
	}

	/*
	 * Add a collection of DERTypes
	 */
	public void add(Collection<DERType> objects) {
		this.objects.addAll(objects);
	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.x509.der.DERType#encode()
	 */
	@Override
	public byte[] encode() throws EncodingException {

		ByteArrayOutputStream accumulator = new ByteArrayOutputStream();
		Iterator<DERType> it = objects.iterator();
		while (it.hasNext()) {
			// Doing this to avoid the silly IOException
			byte[] encoded = it.next().encode();
			accumulator.write(encoded, 0, encoded.length);
		}

		return accumulator.toByteArray();

	}

	/* (non-Javadoc)
	 * @see org.cryptokitty.provider.x509.der.DERType#decode(byte[])
	 */
	@Override
	public int decode(byte[] encoded) throws EncodingException {

		int index = 0;
		while (index < encoded.length) {
			DERType object = DERTags.getDERType(DERTags.getTag(encoded));
			index += object.decode(Arrays.copyOfRange(encoded, index, encoded.length));
			objects.add(object);
		}

		return encoded.length;

	}

}
