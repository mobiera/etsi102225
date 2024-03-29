package com.mobiera.lib.etsi102225.impl.crypto.mac;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mobiera.lib.etsi102225.impl.crypto.CipherParameters;
import com.mobiera.lib.etsi102225.impl.crypto.Mac;
import com.mobiera.lib.etsi102225.impl.crypto.params.KeyParameter;
import com.mobiera.lib.etsi102225.impl.crypto.params.ParametersWithIV;

public abstract class AbstractCipherMac implements Mac
{
	private Cipher m_cipher;
	private byte[] m_key;
	private byte[] m_iv;

	private final String m_algFullName;
	private final String m_algShortName;
	private final int m_size;

	AbstractCipherMac(String algFullName, String algShortName, int size)
	{
		m_algFullName = algFullName;
		m_algShortName = algShortName;
		m_size = size;
	}

	@Override
	public void init(CipherParameters cipheringParams) throws IllegalArgumentException
	{
		if (cipheringParams instanceof ParametersWithIV)
		{
			m_iv = ((ParametersWithIV) cipheringParams).getIV();
			if (m_iv == null)
				throw new IllegalArgumentException("IV cannot be null");

			cipheringParams = ((ParametersWithIV) cipheringParams).getParameters();
		}

		if (!(cipheringParams instanceof KeyParameter))
		{
			m_iv = null;
			throw new IllegalArgumentException("cipheringParams must contain KeyParameter");
		}
		m_key = ((KeyParameter) cipheringParams).getKey();
		if (m_key == null)
		{
			m_iv = null;
			throw new IllegalArgumentException("Key cannot be null");
		}
		try
		{
			m_cipher = Cipher.getInstance(m_algFullName);

			Key keySpec = new SecretKeySpec(m_key, m_algShortName);
			if (m_iv != null)
				m_cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(m_iv));
			else
				m_cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		}

		catch (GeneralSecurityException ex)
		{
			throw new IllegalArgumentException(ex);
		}
	}

	@Override
	public String getAlgorithmName()
	{
		return m_algFullName;
	}

	@Override
	public int getMacSize()
	{
		return m_size;
	}

	@Override
	public void update(byte input) throws IllegalStateException
	{
		m_cipher.update(new byte[] { input });
	}

	@Override
	public void update(byte[] input, int inputOffset, int inputLen) throws  IllegalStateException
	{
		m_cipher.update(input, inputOffset, inputLen);
	}

	@Override
	public int doFinal(byte[] output, int outputOffset) throws  IllegalStateException
	{
		try
		{
			byte[] result = m_cipher.doFinal();
			// BUGFIX: take most significant bytes instead of least significant ones
			//System.arraycopy(result, result.length - m_size, output, outputOffset, m_size);
			System.arraycopy(result, 0, output, outputOffset, m_size);
			return m_size;
		} catch (IllegalBlockSizeException e)
		{
			e.printStackTrace();
		} catch (BadPaddingException e)
		{
			e.printStackTrace();
		}
		return 0;
	}

	@Override
	public void reset()
	{
		try
		{
			m_cipher.doFinal();
		} catch (IllegalBlockSizeException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
