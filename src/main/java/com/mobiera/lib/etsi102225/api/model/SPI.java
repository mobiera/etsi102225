//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-833 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.09.09 at 04:14:20 PM MSD 
//


package com.mobiera.lib.etsi102225.api.model;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;



@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SPI", propOrder = {

})
public class SPI implements Serializable {

    @XmlElement(name = "CommandSPI", required = true)
    protected CommandSPI commandSPI;
    @XmlElement(name = "ResponseSPI", required = true)
    protected ResponseSPI responseSPI;

    /**
     * Gets the value of the commandSPI property.
     * 
     * @return
     *     possible object is
     *     {@link CommandSPI }
     *     
     */
    public CommandSPI getCommandSPI() {
        return commandSPI;
    }

    /**
     * Sets the value of the commandSPI property.
     * 
     * @param value
     *     allowed object is
     *     {@link CommandSPI }
     *     
     */
    public void setCommandSPI(CommandSPI value) {
        this.commandSPI = value;
    }

    /**
     * Gets the value of the responseSPI property.
     * 
     * @return
     *     possible object is
     *     {@link ResponseSPI }
     *     
     */
    public ResponseSPI getResponseSPI() {
        return responseSPI;
    }

    /**
     * Sets the value of the responseSPI property.
     * 
     * @param value
     *     allowed object is
     *     {@link ResponseSPI }
     *     
     */
    public void setResponseSPI(ResponseSPI value) {
        this.responseSPI = value;
    }

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = 1;
		result = prime * result + ((commandSPI == null) ? 0 : commandSPI.hashCode());
		result = prime * result + ((responseSPI == null) ? 0 : responseSPI.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof SPI))
			return false;
		SPI other = (SPI) obj;
		if (commandSPI == null)
		{
			if (other.commandSPI != null)
				return false;
		}
		else if (!commandSPI.equals(other.commandSPI))
			return false;
		if (responseSPI == null)
		{
			if (other.responseSPI != null)
				return false;
		}
		else if (!responseSPI.equals(other.responseSPI))
			return false;
		return true;
	}

	@Override
	public String toString()
	{
		StringBuilder builder = new StringBuilder();
		builder.append("SPI [commandSPI=");
		builder.append(commandSPI);
		builder.append(", responseSPI=");
		builder.append(responseSPI);
		builder.append("]");
		return builder.toString();
	}

}
