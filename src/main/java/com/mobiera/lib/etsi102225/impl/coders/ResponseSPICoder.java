package com.mobiera.lib.etsi102225.impl.coders;

import com.mobiera.lib.etsi102225.api.model.CertificationMode;
import com.mobiera.lib.etsi102225.api.model.PoRMode;
import com.mobiera.lib.etsi102225.api.model.PoRProtocol;
import com.mobiera.lib.etsi102225.api.model.ResponseSPI;
import com.mobiera.lib.etsi102225.impl.CodingException;
import com.mobiera.lib.etsi102225.impl.Util;

public class ResponseSPICoder
{
	public static byte decode(ResponseSPI responseSPI) throws CodingException
	{
		int certMode = 0;
		int porProtocol = 0;
		int porMode = 0;
		boolean isCiphered = responseSPI.isCiphered();

		switch (responseSPI.getPoRCertificateMode())
		{
			case NO_SECURITY:
				certMode = 0;
				break;
			case RC:
				certMode = 1;
				break;
			case CC:
				certMode = 2;
				break;
			case DS:
				certMode = 3;
				break;
		}

		switch (responseSPI.getPoRMode())
		{
			case NO_REPLY:
				porMode = 0;
				break;
			case REPLY_ALWAYS:
				porMode = 1;
				break;
			case REPLY_WHEN_ERROR:
				porMode = 2;
				break;
			case RESERVED:
				porMode = 3;
				break;
		}

		switch (responseSPI.getPoRProtocol())
		{
			case SMS_DELIVER_REPORT:
				porProtocol = 0;
				break;
			case SMS_SUBMIT:
				porProtocol = 1;
				break;
		}
		
		byte result = (byte) (porMode + (certMode << 2) + (porProtocol << 5));
		if (isCiphered)
			result = (byte) (result | (1 << 4));

		return result;
	}

	public static ResponseSPI encode(byte responseSPI) throws CodingException
	{
		ResponseSPI result = new ResponseSPI();

		final int certMode = (responseSPI & 0xC) >> 2;
		final int porProtocol = (responseSPI & 0x20) >> 5;
		final int porMode = responseSPI & 0x3;
		boolean isCiphered = (responseSPI & 0x10) != 0;

		CertificationMode resultCertMode = null;
		switch (certMode)
		{
			case 0:
				resultCertMode = CertificationMode.NO_SECURITY;
				break;
			case 1:
				resultCertMode = CertificationMode.RC;
				break;
			case 2:
				resultCertMode = CertificationMode.CC;
				break;
			case 3:
				resultCertMode = CertificationMode.DS;
				break;

			default:
				throw new CodingException("Cannot encode ResponseSPI(raw=" + Util.toHex(responseSPI) + "). No such certification mode(raw="
						+ Integer.toHexString(certMode));
		}

		PoRProtocol resultPorProtocol = null;
		switch (porProtocol)
		{
			case 0:
				resultPorProtocol = PoRProtocol.SMS_DELIVER_REPORT;
				break;
			case 1:
				resultPorProtocol = PoRProtocol.SMS_SUBMIT;
				break;

			default:
				throw new CodingException("Cannot encode ResponseSPI(raw=" + Util.toHex(responseSPI) + "). No such POR protocol(raw="
						+ Integer.toHexString(porProtocol));
		}

		PoRMode resultPorMode = null;
		switch (porMode)
		{
			case 0:
				resultPorMode = PoRMode.NO_REPLY;
				break;
			case 1:
				resultPorMode = PoRMode.REPLY_ALWAYS;
				break;
			case 2:
				resultPorMode = PoRMode.REPLY_WHEN_ERROR;
				break;
			case 3:
				resultPorMode = PoRMode.RESERVED;
				break;
			default:
				throw new CodingException("Cannot encode ResponseSPI(raw=" + Util.toHex(responseSPI) + "). No such POR mode(raw="
						+ Integer.toHexString(porProtocol));
		}
		
		result.setCiphered(isCiphered);
		result.setPoRCertificateMode(resultCertMode);
		result.setPoRMode(resultPorMode);
		result.setPoRProtocol(resultPorProtocol);

		return result;
	}
}
