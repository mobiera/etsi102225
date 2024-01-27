package com.mobiera.lib.etsi102225.api;

/**
 * General library exception
 * 
 * @author Victor Platov
 * */
public class Etsi102225Exception extends Exception
{
	private static final long serialVersionUID = -593113341925505030L;

	public Etsi102225Exception()
	{
	}

	public Etsi102225Exception(String message)
	{
		super(message);
	}

	public Etsi102225Exception(Throwable cause)
	{
		super(cause);
	}

	public Etsi102225Exception(String message, Throwable cause)
	{
		super(message, cause);
	}

}
