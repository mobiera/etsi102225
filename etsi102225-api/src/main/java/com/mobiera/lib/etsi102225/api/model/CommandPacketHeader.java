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
@XmlType(name = "CommandPacketHeader", propOrder = {
    "spi",
    "kic",
    "kid"
})
public class CommandPacketHeader
    extends SecurityHeader implements Serializable
{

    @XmlElement(name = "SPI", required = true)
    protected SPI spi;
    @XmlElement(name = "KIC", required = true)
    protected KIC kic;
    @XmlElement(name = "KID", required = true)
    protected KID kid;

    /**
     * Gets the value of the spi property.
     * 
     * @return
     *     possible object is
     *     {@link SPI }
     *     
     */
    public SPI getSPI() {
        return spi;
    }

    /**
     * Sets the value of the spi property.
     * 
     * @param value
     *     allowed object is
     *     {@link SPI }
     *     
     */
    public void setSPI(SPI value) {
        this.spi = value;
    }

    /**
     * Gets the value of the kic property.
     * 
     * @return
     *     possible object is
     *     {@link KIC }
     *     
     */
    public KIC getKIC() {
        return kic;
    }

    /**
     * Sets the value of the kic property.
     * 
     * @param value
     *     allowed object is
     *     {@link KIC }
     *     
     */
    public void setKIC(KIC value) {
        this.kic = value;
    }

    /**
     * Gets the value of the kid property.
     * 
     * @return
     *     possible object is
     *     {@link KID }
     *     
     */
    public KID getKID() {
        return kid;
    }

    /**
     * Sets the value of the kid property.
     * 
     * @param value
     *     allowed object is
     *     {@link KID }
     *     
     */
    public void setKID(KID value) {
        this.kid = value;
    }

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((kic == null) ? 0 : kic.hashCode());
		result = prime * result + ((kid == null) ? 0 : kid.hashCode());
		result = prime * result + ((spi == null) ? 0 : spi.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (!(obj instanceof CommandPacketHeader))
			return false;
		CommandPacketHeader other = (CommandPacketHeader) obj;
		if (kic == null)
		{
			if (other.kic != null)
				return false;
		}
		else if (!kic.equals(other.kic))
			return false;
		if (kid == null)
		{
			if (other.kid != null)
				return false;
		}
		else if (!kid.equals(other.kid))
			return false;
		if (spi == null)
		{
			if (other.spi != null)
				return false;
		}
		else if (!spi.equals(other.spi))
			return false;
		return true;
	}

	@Override
	public String toString()
	{
		StringBuilder builder = new StringBuilder();
		builder.append("CommandPacketHeader [spi=");
		builder.append(spi);
		builder.append(", kic=");
		builder.append(kic);
		builder.append(", kid=");
		builder.append(kid);
		builder.append(", tar=");
		builder.append(Arrays.toString(tar));
		builder.append(", paddingCounter=");
		builder.append(paddingCounter);
		builder.append(", security=");
		builder.append(Arrays.toString(security));
		builder.append(", counter=");
		builder.append(Arrays.toString(counter));
		builder.append("]");
		return builder.toString();
	}

}
