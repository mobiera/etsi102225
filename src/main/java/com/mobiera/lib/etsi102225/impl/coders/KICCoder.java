package com.mobiera.lib.etsi102225.impl.coders;

import com.mobiera.lib.etsi102225.api.model.AlgorithmImplementation;
import com.mobiera.lib.etsi102225.api.model.CipheringAlgorithmMode;
import com.mobiera.lib.etsi102225.api.model.KIC;
import com.mobiera.lib.etsi102225.impl.CodingException;
import com.mobiera.lib.etsi102225.impl.Util;

public class KICCoder
{
	public static byte decode(KIC kic) throws CodingException
	{
		int algImpl = 0;
		int algMode = 0;
		byte keysetID = kic.getKeysetID();

		if(keysetID  < 0 && keysetID > 0xF)
			throw new CodingException("Cannot decode KIC. KIC keySetID cannot be <0 and >15");

		switch (kic.getAlgorithmImplementation())
		{
		case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
			algImpl = 0;
			break;
		case DES:
			algImpl = 1;
			break;
		case RESERVED:
			algImpl = 2;
			break;
		case PROPRIETARY_IMPLEMENTATIONS:
			algImpl = 3;
			break;
		case AES:
			algImpl = 2;
			break;
		}

		switch (kic.getCipheringAlgorithmMode())
		{
		case DES_CBC:
			algMode = 0;
			break;
		case TRIPLE_DES_CBC_2_KEYS:
			algMode = 1;
			break;
		case TRIPLE_DES_CBC_3_KEYS:
			algMode = 2;
			break;
		case DES_ECB:
			algMode = 3;
			break;
		case AES_CBC:
			algMode = 0;
			break;
		}

		byte result = (byte)(algImpl + (algMode << 2) + (keysetID << 4));

		return result;
	}

	public static KIC encode(byte kic) throws CodingException
	{
		KIC result = new KIC();

		final int algImpl = kic & 0x3;
		final int algMode = (kic & 0xC) >> 2;
		final byte keysetID = (byte) ((kic & 0xF0) >>> 4);

		AlgorithmImplementation resultAlgImpl = null;
		switch (algImpl)
		{
		case 0:
			resultAlgImpl = AlgorithmImplementation.ALGORITHM_KNOWN_BY_BOTH_ENTITIES;
			break;
		case 1:
			resultAlgImpl = AlgorithmImplementation.DES;
			break;
		case 2:
			resultAlgImpl = AlgorithmImplementation.AES;
			break;
		case 3:
			resultAlgImpl = AlgorithmImplementation.PROPRIETARY_IMPLEMENTATIONS;
			break;

		default:
			throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). No such algorithm implemetation(raw="
					+ Integer.toHexString(algImpl));
		}

		CipheringAlgorithmMode resultAlgMode = null;
		if (resultAlgImpl == AlgorithmImplementation.DES) {
			switch (algMode)
			{
				case 0:
					resultAlgMode = CipheringAlgorithmMode.DES_CBC;
					break;
				case 1:
					resultAlgMode = CipheringAlgorithmMode.TRIPLE_DES_CBC_2_KEYS;
					break;
				case 2:
					resultAlgMode = CipheringAlgorithmMode.TRIPLE_DES_CBC_3_KEYS;
					break;
				case 3:
					resultAlgMode = CipheringAlgorithmMode.DES_ECB;
					break;

				default:
					throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). No such algorithm mode(raw="
						+ Integer.toHexString(algMode));
			} 
		} else if (resultAlgImpl == AlgorithmImplementation.AES) {
			switch (algMode)
			{
			case 0:
				resultAlgMode = CipheringAlgorithmMode.AES_CBC;
				break;

			default:
				throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). No such algorithm mode(raw="
						+ Integer.toHexString(algMode));
			}
		}
	


	if(keysetID  < 0 && keysetID > 0xF)
		throw new CodingException("Cannot encode KIC(raw=" + Util.toHex(kic) + "). KIC keySetID cannot be <0 and >15");

	result.setAlgorithmImplementation(resultAlgImpl);
	result.setCipheringAlgorithmMode(resultAlgMode);
	result.setKeysetID(keysetID);

	return result;
}
}
