package com.mobiera.lib.etsi102225.impl.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

import com.mobiera.lib.etsi102225.impl.crypto.mac.AESCMAC;
import com.mobiera.lib.etsi102225.impl.crypto.mac.CRC32MAC;
import com.mobiera.lib.etsi102225.impl.crypto.mac.DESMACISO9797M1;
import com.mobiera.lib.etsi102225.impl.crypto.params.KeyParameter;
import com.mobiera.lib.etsi102225.impl.crypto.params.ParametersWithIV;

/**
 * This utility class is used for signature operations during GSM 03.48 packet
 * creation and recovering. It performs redundancy check, digital signature and
 * cryptographic checksum algorithms.
 * 
 * @author Victor Platov
 */
public class SignatureManager
{
	private static final Logger LOGGER = Logger.getLogger(SignatureManager.class);
	public static final String DES_MAC8_ISO9797_M1 = "DES_MAC8_ISO9797_M1";
	public static final String CRC32 = "CRC32";
	public static final String AES_CMAC4 = "AES_CMAC4";
	public static final String AES_CMAC8 = "AES_CMAC8";
	
	private SignatureManager()
	{
	}

	private static Mac getMac(String algName, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating MAC for name:" + algName + " with key length " + key.length);
		Mac mac = Mac.getInstance(algName);
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("MAC length:" + mac.getMacLength());
		SecretKeySpec keySpec = new SecretKeySpec(key, algName);
		mac.init(keySpec);
		return mac;
	}
	private static byte[] runOwnMac(com.mobiera.lib.etsi102225.impl.crypto.Mac mac,byte[] key,byte[] data, byte[] iv)
	{
		CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
		mac.init(params);
		mac.update(data, 0, data.length);
		byte[] result = new byte[mac.getMacSize()];
		mac.doFinal(result, 0);
		return result;
	}
	public static byte[] sign(String algName, byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Signing. Data length:" + data.length);
		if(DES_MAC8_ISO9797_M1.equals(algName)) return runOwnMac(new DESMACISO9797M1(),key,data, new byte[8]);
		if(CRC32.equals(algName)) return runOwnMac(new CRC32MAC(),key,data, new byte[8]);
		if(AES_CMAC4.equals(algName)) return runOwnMac(new AESCMAC(4),key,data, new byte[16]);
		if(AES_CMAC8.equals(algName)) return runOwnMac(new AESCMAC(8),key,data, new byte[16]);
		
		return doWork(algName, key, data);
	}

	public static boolean verify(String algName, byte[] key, byte[] data, byte[] signature) throws NoSuchAlgorithmException,
			InvalidKeyException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Verifying. Data length:" + data.length);

		return Arrays.equals(signature, sign(algName, key, data));
	}

	private static byte[] doWork(String algName, byte[] key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException
	{
		Mac mac = getMac(algName, key);
		byte[] result = mac.doFinal(data);
		return result;
	}

	public static int signLength(String algName) throws NoSuchAlgorithmException
	{
		if(DES_MAC8_ISO9797_M1.equals(algName)) // TODO: remove this block after adding something better
		{
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("Creating MAC for name:" + algName);
			
			final int macLength = 8;
			
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("MAC length:" + macLength);
			return macLength;
		} else if(CRC32.equals(algName)) 
		{
			return 4;
		} else if(AES_CMAC4.equals(algName)) {
			return 4;
		} else if(AES_CMAC8.equals(algName)) {
			return 8;
		}
		
		Mac mac = Mac.getInstance(algName);
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating MAC for name:" + algName);
		
		final int macLength = mac.getMacLength();
		
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("MAC length:" + macLength);
		return macLength;
	}

	public static byte[] sing(String signatureAlgorithmName, byte[] signatureKey, byte[] signData)
	{
		// TODO Auto-generated method stub
		return null;
	}
}
