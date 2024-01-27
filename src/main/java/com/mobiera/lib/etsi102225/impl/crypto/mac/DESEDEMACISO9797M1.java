package com.mobiera.lib.etsi102225.impl.crypto.mac;


public class DESEDEMACISO9797M1 extends AbstractCipherMac
{
	
	public DESEDEMACISO9797M1()
	{
		super("DESEDE/CBC/ZeroBytePadding","DESEDE",8);
	}
}
