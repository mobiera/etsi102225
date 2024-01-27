package com.mobiera.lib.etsi102225.impl.crypto.mac;

public class DESMACISO9797M1 extends AbstractCipherMac
{
	public DESMACISO9797M1()
	{
		super("DES/CBC/ZeroBytePadding","DES",8);
	}
}
