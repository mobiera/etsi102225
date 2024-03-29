package com.mobiera.lib.etsi102225.impl;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.apache.log4j.Logger;

import com.mobiera.lib.etsi102225.impl.crypto.CipheringManager;
import com.mobiera.lib.etsi102225.impl.crypto.Util;

public class ICCIDKeyGenerator
{

	private static final Logger LOGGER = Logger.getLogger(ICCIDKeyGenerator.class);

	private static final int ICCID_LENGTH = 20;
	private static final int ICCID_LENGTH_WITHOUT_LUHN = 19;
	private static final String TRANSFORMATION =  "DES/ECB/NoPadding";

	
	public static byte[] getKey(byte[] masterKey, String iccid) throws GeneralSecurityException
	{
		if (iccid == null || iccid.isEmpty())
			throw new IllegalArgumentException("ICCID cannot be null or empty. Now is iccid=" + iccid);
		if (iccid.length() != ICCID_LENGTH && iccid.length() != ICCID_LENGTH_WITHOUT_LUHN)
			throw new IllegalArgumentException("ICCID length must be ether " + ICCID_LENGTH + " or " + ICCID_LENGTH_WITHOUT_LUHN
					+ ". ICCID=" + iccid + " length=" + iccid.length());

		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Generating ciphering key. Master key = " + Util.toHexArray(masterKey) + ", ICCID=" + iccid);
		if (iccid.length() == ICCID_LENGTH_WITHOUT_LUHN)
		{
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("ICCID provided without Luhn number - trying to add");
			iccid = addLuhn(iccid);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("New ICCID with Luhn number: " + iccid);
		}
		if (!verifyLuhnChecksum(iccid))
			throw new IllegalArgumentException("ICCID has bad checksum");

		byte[] byteIccid = new byte[iccid.length() / 2];

		for (int i = 0; i < iccid.length(); i += 2)
		{
			byteIccid[i / 2] = (byte) Integer.parseInt(iccid.substring(i, i + 2), 0x10);
		}
		return getKey(masterKey, byteIccid);
	}

	
	public static byte[] getKey(byte[] masterKey, byte[] iccid) throws GeneralSecurityException
	{
		if (masterKey == null || masterKey.length != 8)
			throw new IllegalArgumentException("Master key cannot be null or not 8-bytes length. MasterKey="
					+ Util.toHexArray(masterKey));
		if (iccid == null || iccid.length < 8)
			throw new IllegalArgumentException("ICCID cannot be null or less than 8-bytes length. ICCID="
					+ Util.toHexArray(iccid));

		if (iccid.length > 8)
		{
			iccid = Arrays.copyOfRange(iccid, iccid.length - 8, iccid.length);
			if (LOGGER.isDebugEnabled())
				LOGGER.debug("ICCID length > 8 - using last 8 bytes: " + iccid);
		}
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Generating key. Master key: " + Util.toHexArray(masterKey) + ", ICCID= " + Util.toHexArray(iccid));
		
		byte[] result = CipheringManager.encipher(TRANSFORMATION, masterKey, iccid, new byte[8]);
		
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Generated key: " + Util.toHexArray(result));
		
		return result;
	}

	
	public static boolean verifyLuhnChecksum(String input)
	{
		final int[][] sumTable = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 } };
		int sum = 0, flip = 0;

		for (int i = input.length() - 1; i >= 0; i--)
			sum += sumTable[flip++ & 0x1][Character.digit(input.charAt(i), 10)];

		final boolean result = sum % 10 == 0;

		if (result && LOGGER.isDebugEnabled())
			LOGGER.debug("Checksum check for " + input + " is: PASSED");
		if (!result)
			LOGGER.error("Checksum check for " + input + " is: FAILED");
		return result;
	}

	private static String addLuhn(String input)
	{
		byte[] byteIccid = new byte[input.length() + 1];
		for (int i = 0; i < input.length(); i++)
		{
			byteIccid[i] = (byte) (Character.digit(input.charAt(i), 10));
		}

		return input + getLuhn(byteIccid);
	}

	private static byte getLuhn(byte[] input)
	{
		int result = 0;
		int tmp = 0;
		for (int i = 0; i < input.length; i++)
		{
			tmp = input[input.length - i - 1];
			if (i % 2 != 0)
			{
				tmp *= 2;
				if (tmp > 9)
					tmp -= 9;
			}
			result += tmp;
		}
		result = 10 - (result % 10);
		if(result == 10) result = 0; // Strange workaround since this algo never adds "0" 
		return (byte) result;
	}
}
