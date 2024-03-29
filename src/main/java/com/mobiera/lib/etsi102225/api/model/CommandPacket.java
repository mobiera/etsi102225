//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-833 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.09.09 at 04:14:20 PM MSD 
//


package com.mobiera.lib.etsi102225.api.model;

import java.io.Serializable;
import java.util.Arrays;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;



@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CommandPacket", propOrder = {
    "header"
})
public class CommandPacket
    extends Packet implements Serializable
{

    @XmlElement(name = "Header", required = true)
    protected CommandPacketHeader header;

    /**
     * Gets the value of the header property.
     * 
     * @return
     *     possible object is
     *     {@link CommandPacketHeader }
     *     
     */
    public CommandPacketHeader getHeader() {
        return header;
    }

    /**
     * Sets the value of the header property.
     * 
     * @param value
     *     allowed object is
     *     {@link CommandPacketHeader }
     *     
     */
    public void setHeader(CommandPacketHeader value) {
        this.header = value;
    }

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((header == null) ? 0 : header.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (!(obj instanceof CommandPacket))
			return false;
		CommandPacket other = (CommandPacket) obj;
		if (header == null)
		{
			if (other.header != null)
				return false;
		}
		else if (!header.equals(other.header))
			return false;
		return true;
	}

	@Override
	public String toString()
	{
		StringBuilder builder = new StringBuilder();
		builder.append("CommandPacket [header=");
		builder.append(header);
		builder.append(", data=");
		builder.append(Arrays.toString(data));
		builder.append("]");
		return builder.toString();
	}

}
