package com.mobiera.lib.etsi102225.impl.coders;

import com.mobiera.lib.etsi102225.api.model.AlgorithmImplementation;
import com.mobiera.lib.etsi102225.api.model.CertificationAlgorithmMode;
import com.mobiera.lib.etsi102225.api.model.KID;
import com.mobiera.lib.etsi102225.impl.CodingException;
import com.mobiera.lib.etsi102225.impl.Util;

public class KIDCoder
{
	public static byte decode(KID kid) throws CodingException
	{
	    int algImpl = 0;
	    int algMode = 0;
	    byte keysetID = kid.getKeysetID();

	    if (keysetID < 0 && keysetID > 0xF) {
	      throw new CodingException("Cannot decode KID. KID keySetID cannot be <0 and >15");
	    }

	    if (kid.getAlgorithmImplementation() != null) {
	      switch (kid.getAlgorithmImplementation()) {
	        case ALGORITHM_KNOWN_BY_BOTH_ENTITIES:
	          algImpl = 0;
	          break;
	        case DES:
	        case CRC:
	          algImpl = 1;
	          break;
	        case AES:
	          algImpl = 2;
	          break;
	        case PROPRIETARY_IMPLEMENTATIONS:
	          algImpl = 3;
	          break;
	      }
	    } else {
	      algImpl = 0;
	    }

	    if (kid.getCertificationAlgorithmMode() != null) {
	      switch (kid.getCertificationAlgorithmMode()) {
	        case DES_CBC:
	        case AES_CMAC4:
	        case AES_CMAC8:
	        case CRC16:
	          algMode = 0;
	          break;
	        case TRIPLE_DES_CBC_2_KEYS:
	        case CRC32:
	          algMode = 1;
	          break;
	        case TRIPLE_DES_CBC_3_KEYS:
	          algMode = 2;
	          break;
	        case RESERVED:
	          algMode = 3;
	          break;
	      }
	    }

	    byte result = (byte) (algImpl + (algMode << 2) + (keysetID << 4));

	    return result;
	  }

	public static KID encode(byte kid) throws CodingException
	{
		KID result = new KID();

		final int algImpl = kid & 0x3;
		final int algMode = (kid & 0xC) >> 2;
		final byte keysetID = (byte) ((kid & 0xF0) >>> 4);

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
				throw new CodingException("Cannot encode KID(raw=" + Util.toHex(kid) + "). No such algorithm implemetation(raw="
						+ Integer.toHexString(algImpl));
		}
		
		CertificationAlgorithmMode resultAlgMode = null;
		
		if (resultAlgImpl == AlgorithmImplementation.DES) {
			switch (algMode)
			{
				case 0:
					resultAlgMode = CertificationAlgorithmMode.DES_CBC;
					break;
				case 1:
					resultAlgMode = CertificationAlgorithmMode.TRIPLE_DES_CBC_2_KEYS;
					break;
				case 2:
					resultAlgMode = CertificationAlgorithmMode.TRIPLE_DES_CBC_3_KEYS;
					break;
				case 3:
					resultAlgMode = CertificationAlgorithmMode.RESERVED;
					break;

				default:
					throw new CodingException("Cannot encode KID(raw=" + Util.toHex(kid) + "). No such algorithm mode(raw="
							+ Integer.toHexString(algMode));
			}
		} else if (resultAlgImpl == AlgorithmImplementation.AES) {
			switch (algMode)
			{
				case 0:
					resultAlgMode = CertificationAlgorithmMode.AES_CMAC8; // Default to 8-byte CMAC
					break;
				case 1:
					resultAlgMode = CertificationAlgorithmMode.RESERVED;
					break;
				case 2:
					resultAlgMode = CertificationAlgorithmMode.RESERVED;
					break;
				case 3:
					resultAlgMode = CertificationAlgorithmMode.RESERVED;
					break;

				default:
					throw new CodingException("Cannot encode KID(raw=" + Util.toHex(kid) + "). No such algorithm mode(raw="
							+ Integer.toHexString(algMode));
			}
		}
		
		if(keysetID  < 0 && keysetID > 0xF)
			throw new CodingException("Cannot encode KID(raw=" + Util.toHex(kid) + "). KID keySetID cannot be <0 and >15");
		
		result.setAlgorithmImplementation(resultAlgImpl);
		result.setCertificationAlgorithmMode(resultAlgMode);
		result.setKeysetID(keysetID);
		
		return result;
	}
}
