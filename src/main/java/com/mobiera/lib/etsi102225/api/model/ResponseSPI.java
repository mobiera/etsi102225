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
@XmlType(name = "ResponseSPI", propOrder = {

})
public class ResponseSPI implements Serializable {

    @XmlElement(name = "PoRProtocol", required = true)
    protected PoRProtocol poRProtocol;
    @XmlElement(name = "PoRMode", required = true)
    protected PoRMode poRMode;
    @XmlElement(name = "PoRCertificateMode", required = true)
    protected CertificationMode poRCertificateMode;
    @XmlElement(name = "Ciphered")
    protected boolean ciphered;

    /**
     * Gets the value of the poRProtocol property.
     * 
     * @return
     *     possible object is
     *     {@link PoRProtocol }
     *     
     */
    public PoRProtocol getPoRProtocol() {
        return poRProtocol;
    }

    /**
     * Sets the value of the poRProtocol property.
     * 
     * @param value
     *     allowed object is
     *     {@link PoRProtocol }
     *     
     */
    public void setPoRProtocol(PoRProtocol value) {
        this.poRProtocol = value;
    }

    /**
     * Gets the value of the poRMode property.
     * 
     * @return
     *     possible object is
     *     {@link PoRMode }
     *     
     */
    public PoRMode getPoRMode() {
        return poRMode;
    }

    /**
     * Sets the value of the poRMode property.
     * 
     * @param value
     *     allowed object is
     *     {@link PoRMode }
     *     
     */
    public void setPoRMode(PoRMode value) {
        this.poRMode = value;
    }

    /**
     * Gets the value of the poRCertificateMode property.
     * 
     * @return
     *     possible object is
     *     {@link CertificationMode }
     *     
     */
    public CertificationMode getPoRCertificateMode() {
        return poRCertificateMode;
    }

    /**
     * Sets the value of the poRCertificateMode property.
     * 
     * @param value
     *     allowed object is
     *     {@link CertificationMode }
     *     
     */
    public void setPoRCertificateMode(CertificationMode value) {
        this.poRCertificateMode = value;
    }

    /**
     * Gets the value of the ciphered property.
     * 
     */
    public boolean isCiphered() {
        return ciphered;
    }

    /**
     * Sets the value of the ciphered property.
     * 
     */
    public void setCiphered(boolean value) {
        this.ciphered = value;
    }

	@Override
	public int hashCode()
	{
		final int prime = 31;
		int result = 1;
		result = prime * result + (ciphered ? 1231 : 1237);
		result = prime * result + ((poRCertificateMode == null) ? 0 : poRCertificateMode.hashCode());
		result = prime * result + ((poRMode == null) ? 0 : poRMode.hashCode());
		result = prime * result + ((poRProtocol == null) ? 0 : poRProtocol.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof ResponseSPI))
			return false;
		ResponseSPI other = (ResponseSPI) obj;
		if (ciphered != other.ciphered)
			return false;
		if (poRCertificateMode != other.poRCertificateMode)
			return false;
		if (poRMode != other.poRMode)
			return false;
		if (poRProtocol != other.poRProtocol)
			return false;
		return true;
	}

	@Override
	public String toString()
	{
		StringBuilder builder = new StringBuilder();
		builder.append("ResponseSPI [poRProtocol=");
		builder.append(poRProtocol);
		builder.append(", poRMode=");
		builder.append(poRMode);
		builder.append(", poRCertificateMode=");
		builder.append(poRCertificateMode);
		builder.append(", ciphered=");
		builder.append(ciphered);
		builder.append("]");
		return builder.toString();
	}

}
