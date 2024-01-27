package com.mobiera.lib.etsi102225.impl;

import com.mobiera.lib.etsi102225.api.Etsi102225Exception;

public class CodingException extends Etsi102225Exception
{
	private static final long serialVersionUID = 1L;

	public CodingException()
	{
	}

	public CodingException(String message)
	{
		super(message);
	}

	public CodingException(Throwable cause)
	{
		super(cause);
	}

	public CodingException(String message, Throwable cause)
	{
		super(message, cause);
	}
}
