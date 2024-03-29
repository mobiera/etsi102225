package com.mobiera.lib.etsi102225.api;

/**
 * This exception is used to signal any problems with {@linkplain PacketBuilder}
 * configuration.
 * 
 * @author Victor Platov
 */
public class PacketBuilderConfigurationException extends Etsi102225Exception
{
	private static final long serialVersionUID = -7552859618503923645L;

	public PacketBuilderConfigurationException()
	{
	}

	public PacketBuilderConfigurationException(final String message)
	{
		super(message);
	}

	public PacketBuilderConfigurationException(final Throwable cause)
	{
		super(cause);
	}

	public PacketBuilderConfigurationException(final String message, final Throwable cause)
	{
		super(message, cause);
	}
}
