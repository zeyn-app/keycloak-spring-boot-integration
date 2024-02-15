package com.zeyn_app.keycloak.configuration;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();
    private final KeyCloakConfiguration properties;

    public JwtAuthConverter(KeyCloakConfiguration properties){
        this.properties = properties;
    }

    // Bir JWT token'ını alır ve Spring Security'nin kimlik doğrulaması ve yetkilendirme işlemlerinde kullanabileceği
    // bir JwtAuthenticationToken nesnesine dönüştürür.
    // Dönüşüm sırasında, token'daki kullanıcı bilgilerini ve rollerini ayıklar.
    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractRoles(jwt).stream())
                .collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities, getPrincipleName(jwt));
    }

    // Token'daki kullanıcı adını elde etmek için kullanılan claim'i belirler.
    // Varsayılan olarak sub claim'ini kullanır, ancak properties.getPrincipleAttribute() değerine göre
    // özelleştirilebilir. KeyCloakConfiguration sınıfı ile birlikte çalışır ve bu sınıftan alınan konfigürasyon
    // değerlerine göre bu özelleştirilme işlemi yapılır.
    private String getPrincipleName(Jwt jwt){
        String name = JwtClaimNames.SUB;

        if(properties.getPrincipleAttribute()!=null){
            name = properties.getPrincipleAttribute();
        }

        return jwt.getClaim(name);
    }

    // Bu metot jwt token'ı içindeki resource_access claim'inden kaynak sunucusuna özel rolleri ayıklamayı sağlar.
    // Yani bu rolleri Spring Security'nin anlayabileceği GrantedAuthority nesnelerine dönüştürür.
    // Rollerin başında ROLE_ olmalı, bu metod ile bunu sağlıyoruz.
    private Collection<? extends GrantedAuthority> extractRoles(Jwt jwt){
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");

        Map<String, Object> resource;
        Collection<String> resourceRoles;

        if(resourceAccess==null
        || (resource = (Map<String, Object>) resourceAccess.get(properties.getResourceId())) == null
        || (resourceRoles = (Collection<String>) resource.get("roles")) == null){
            return Set.of();
        }

        return resourceRoles.stream()
                .map(role-> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

}
