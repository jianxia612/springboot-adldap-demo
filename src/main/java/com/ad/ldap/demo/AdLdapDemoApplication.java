package com.ad.ldap.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@SpringBootApplication
public class AdLdapDemoApplication {
	
	 /*
	    * SpringLdap配置。通过@Value注解读取之前配置文件中的值
	    */
	    @Value("${ldap.url}")
	    private String ldapUrl;

	    @Value("${ldap.base}")
	    private String ldapBase;

	    @Value("${ldap.userDn}")
	    private String ldapUserDn;

	    @Value("${ldap.userPwd}")
	    private String ldapUserPwd;

	    @Value("${ldap.referral}")
	    private String ldapReferral;

	    /*
	    *SpringLdap的javaConfig注入方式
	    */
	    @Bean
	    public LdapTemplate ldapTemplate() {
	        return new LdapTemplate(contextSourceTarget());
	    }

	    @Bean
	    public LdapContextSource contextSourceTarget() {
	        LdapContextSource ldapContextSource = new LdapContextSource();
	        ldapContextSource.setUrl(ldapUrl);
	        ldapContextSource.setBase(ldapBase);
	        ldapContextSource.setUserDn(ldapUserDn);
	        ldapContextSource.setPassword(ldapUserPwd);
	        ldapContextSource.setReferral(ldapReferral);
	        return ldapContextSource;
	    }
	    
		public static void main(String[] args) {
			SpringApplication.run(AdLdapDemoApplication.class, args);
		}

}
