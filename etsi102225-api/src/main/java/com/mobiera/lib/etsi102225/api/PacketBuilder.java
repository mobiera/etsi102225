package com.mobiera.lib.etsi102225.api;

import com.mobiera.lib.etsi102225.api.model.CardProfile;
import com.mobiera.lib.etsi102225.api.model.CommandPacket;
import com.mobiera.lib.etsi102225.api.model.ResponsePacket;
import com.mobiera.lib.etsi102225.api.model.ResponsePacketStatus;


/**
 * @author Victor Platov
 */
public interface PacketBuilder
{
	
	void setProfile(CardProfile cardProfile) throws PacketBuilderConfigurationException;

	
	CardProfile getProfile();

	boolean isConfigured();

	
	byte[] buildCommandPacket(byte[] data, long counters, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Etsi102225Exception;

	
	ResponsePacket recoverResponsePacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Etsi102225Exception;

	
	@Deprecated 
	byte[] buildResponsePacket(byte[] data, byte[] counters, byte[] cipheringKey, byte[] signatureKey,
			ResponsePacketStatus responseStatus) throws PacketBuilderConfigurationException, Etsi102225Exception;

	@Deprecated
	CommandPacket recoverCommandPacket(byte[] data, byte[] cipheringKey, byte[] signatureKey)
			throws PacketBuilderConfigurationException, Etsi102225Exception;
}
