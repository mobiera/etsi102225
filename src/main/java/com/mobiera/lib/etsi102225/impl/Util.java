package com.mobiera.lib.etsi102225.impl;

public class Util
{
	public static String toHex(byte bt)
	{
		return "0x" + Integer.toHexString(bt & 0xFF).toUpperCase();
	}

	private static final char kHexChars[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	private static void appendHexPair(byte b, StringBuilder hexString)
	{
		char highNibble = kHexChars[(b & 0xF0) >> 4];
		char lowNibble = kHexChars[b & 0x0F];
		hexString.append("0x");
		hexString.append(highNibble);
		hexString.append(lowNibble);
	}
 
	public static String toHexArray(byte[] array)
	{
		if (array == null)
			return "null";
		StringBuilder sb = new StringBuilder();
		for (byte b : array)
		{
			appendHexPair(b, sb);
			sb.append(' ');
		}
		if (sb.length() > 0)
			sb.deleteCharAt(sb.length() - 1);
		return sb.toString();
	}

	public static int unsignedByteToInt(byte b)
	{
		return b & 0xFF;
	}

	public static String toUnformattedHexArray(byte[] array)
	{
		StringBuilder sb = new StringBuilder();
		for (byte b : array)
		{
			appendHexPairUnformatted(b, sb);
		}
		return sb.toString();
	}

	private static void appendHexPairUnformatted(byte b, StringBuilder hexString)
	{
		char highNibble = kHexChars[(b & 0xF0) >> 4];
		char lowNibble = kHexChars[b & 0x0F];
		// hexString.append("0x");
		hexString.append(highNibble);
		hexString.append(lowNibble);
	}
}
