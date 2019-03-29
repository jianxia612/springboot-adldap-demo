package com.ad.ldap.demo;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/***
*@purpose:功能说明
*@author:jianxiapc
*@since:2019年3月26日
***/
@RestController
@RequestMapping("/adLdapAuth")
public class JwtAuthController {

    //jwt加密密匙
    @Value("${jwt.key}")
    private String jwtKey;

    //域名后缀
    @Value("${ldap.domainName}")
    private String ldapDomainName;

    //ldap模板
    @Autowired
    private LdapTemplate ldapTemplate;

    /**
     * 将域用户属性通过EmployeeAttributesMapper填充到Employee类中，返回一个填充信息的Employee实例
     */
    private class EmployeeAttributesMapper implements AttributesMapper<AdLdapOrgUser> {
        public AdLdapOrgUser mapFromAttributes(Attributes attrs) throws NamingException, javax.naming.NamingException {
            AdLdapOrgUser adLdapUser = new AdLdapOrgUser();
            adLdapUser.setCommonName((String) attrs.get("sAMAccountName").get());
            adLdapUser.setSuerName((String) attrs.get("distinguishedName").get());
            adLdapUser.setRole((String) attrs.get("memberOf").toString());
            return adLdapUser;
        }
    }

    /**
     * @param username  用户提交的名称
     * @param password  用户提交的密码
     * @return  成功返回加密后的token信息，失败返回错误HTTP状态码
     */
    @CrossOrigin//因为需要跨域访问，所以要加这个注解
    @RequestMapping(value = "loginADAuth",method = RequestMethod.POST)
    public ResponseEntity<String> loginADAuth(
            @RequestParam(value = "username") String username,
            @RequestParam(value = "password") String password) {
        //这里注意用户名加域名后缀  userDn格式：anwx@minibox.com
        String userDn = username + ldapDomainName;
        //token过期时间 4小时
        Date tokenExpired = new Date(new Date().getTime() + 60*60*4*1000);
        DirContext ctx = null;
        try {
            //使用用户名、密码验证域用户
            ctx = ldapTemplate.getContextSource().getContext(userDn, password);
            //如果验证成功根据sAMAccountName属性查询用户名和用户所属的组
            AdLdapOrgUser adLdapUser = ldapTemplate                                                        .search(query().where("objectclass").is("person").and("sAMAccountName").is(username),
                            new EmployeeAttributesMapper())
                    .get(0);
            //使用Jwt加密用户名和用户所属组信息
            String compactJws = Jwts.builder()
                    .setSubject(adLdapUser.getCommonName())
                    //.setAudience(adLdapUser.getRole())
                    .setExpiration(tokenExpired)
                    .signWith(SignatureAlgorithm.HS512, jwtKey).compact();
            //登录成功，返回客户端token信息。这里只加密了用户名和用户角色，而displayName和tokenExpired没有加密
            Map<String, Object> userInfo = new HashMap<String, Object>();
            userInfo.put("token", compactJws);
            userInfo.put("displayName", adLdapUser.getCommonName());
            userInfo.put("tokenExpired", tokenExpired.getTime());
            return new ResponseEntity<String>(JSON.toJSONString(userInfo , SerializerFeature.DisableCircularReferenceDetect) , HttpStatus.OK);
        } catch (Exception e) {
            //登录失败，返回失败HTTP状态码
            return new ResponseEntity<String>(HttpStatus.UNAUTHORIZED);
        } finally {
            //关闭ldap连接
            LdapUtils.closeContext(ctx);
        }
    }

}