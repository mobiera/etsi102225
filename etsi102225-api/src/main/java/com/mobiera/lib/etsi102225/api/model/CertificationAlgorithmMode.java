//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-833 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.09.09 at 04:14:20 PM MSD 
//


package com.mobiera.lib.etsi102225.api.model;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


@XmlType(name = "CertificationAlgorithmMode")
@XmlEnum
public enum CertificationAlgorithmMode {

    DES_CBC,
    TRIPLE_DES_CBC_2_KEYS,
    TRIPLE_DES_CBC_3_KEYS,
    RESERVED,
    CRC16,
    CRC32,
    AES_CMAC4,
    AES_CMAC8;

    public String value() {
        return name();
    }

    public static CertificationAlgorithmMode fromValue(String v) {
        return valueOf(v);
    }

}
