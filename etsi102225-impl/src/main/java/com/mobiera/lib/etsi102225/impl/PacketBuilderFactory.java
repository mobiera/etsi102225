package com.mobiera.lib.etsi102225.impl;

import org.apache.log4j.Logger;

import com.mobiera.lib.etsi102225.api.PacketBuilder;
import com.mobiera.lib.etsi102225.api.PacketBuilderConfigurationException;
import com.mobiera.lib.etsi102225.api.model.CardProfile;

/**
 
 * @author Victor Platov
 */
public class PacketBuilderFactory
{
	private static final Logger LOGGER = Logger.getLogger(PacketBuilderFactory.class);

	private PacketBuilderFactory()
	{

	}

	public static PacketBuilder getInstance(CardProfile cardProfile) throws PacketBuilderConfigurationException
	{
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Creating new PacketBuilder for " + cardProfile);

		return new PacketBuilderImpl(cardProfile);
	}
}
