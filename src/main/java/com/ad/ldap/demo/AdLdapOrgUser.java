package com.ad.ldap.demo;

import lombok.Data;
import org.springframework.ldap.odm.annotations.*;

import javax.naming.Name;

//@Entry(base = "dc=wdcloud,dc=cc", objectClasses = "inetOrgPerson")
@Entry(objectClasses = "inetOrgPerson")
@Data
public class AdLdapOrgUser {

    @Id
    private Name id;
    
    @DnAttribute(value = "uid", index = 3)    
    private String uid;
    
    @Attribute(name = "cn")
    private String commonName; 
    
    @Attribute(name = "memberOf")
    private String role;
    
    @Attribute(name = "sn")
    private String suerName;
    
    private String userPassword;

}
