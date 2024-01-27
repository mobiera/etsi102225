package com.mobiera.lib.etsi102225.impl.crypto.mac;

import java.util.zip.CRC32;

import com.mobiera.lib.etsi102225.impl.crypto.CipherParameters;
import com.mobiera.lib.etsi102225.impl.crypto.Mac;

public class CRC32MAC implements Mac {

	private final int m_size;
	
	private CRC32 m_cipher;

	public CRC32MAC()
	{
		m_cipher = new CRC32();
		m_size = 4;
	}
	
	@Override
	public void init(CipherParameters cipheringParams) throws IllegalArgumentException {
		// Nothing to do
	}

	@Override
	public String getAlgorithmName() {
		return null;
	}

	@Override
	public int getMacSize() {
		return m_size;
	}

	@Override
	public void update(byte input) throws IllegalStateException {
		m_cipher.update(input);
	}

	@Override
	public void update(byte[] input, int inputOffset, int inputLen) throws  IllegalStateException 
	{		
		m_cipher.update(input, inputOffset, inputLen);
	}

	@Override
	public int doFinal(byte[] output, int outputOffset) throws  IllegalStateException {
		long result = m_cipher.getValue();
		
		output[outputOffset]   = (byte)(result >> 24);
		output[outputOffset+1] = (byte)(result >> 16);
		output[outputOffset+2] = (byte)(result >> 8);
		output[outputOffset+3] = (byte)(result);
		
		return 0;
	}

	@Override
	public void reset() {
		m_cipher.reset();
	}

}
