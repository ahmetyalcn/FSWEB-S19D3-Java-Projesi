package com.workintech.auth.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.workintech.auth.util.RsaKeyProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class SecurityConfig {
        private RsaKeyProperty keys;

        @Autowired
        public SecurityConfig(RsaKeyProperty keys) {
            this.keys = keys;
        }

        @Bean
        public JwtDecoder jwtDecoder(){
            return NimbusJwtDecoder.withPublicKey(keys.getPublicKey()).build();
        }
        @Bean
        public JwtEncoder jwtEncoder(){
            JWK jwk = new RSAKey.Builder(keys.getPublicKey()).privateKey(keys.getPrivateKey()).build();
            JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
            return new NimbusJwtEncoder(jwks);
        }

        @Bean
        public JwtAuthenticationConverter jwtAuthenticationConverter(){
            JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
            jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
            jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
            return jwtAuthenticationConverter;
        }
        @Bean
        public PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        }

        @Bean
        public AuthenticationManager authManager(UserDetailsService userDetailsService){
            DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
            daoAuthenticationProvider.setUserDetailsService(userDetailsService);
            daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
            return new ProviderManager(daoAuthenticationProvider);
        }
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
            return http.csrf(csrf-> csrf.disable())
                    .authorizeHttpRequests(auth-> {
                        auth.requestMatchers("/auth/**").permitAll();
                        auth.requestMatchers(HttpMethod.GET, "/account/**", "/student/**")
                                .hasAnyRole("USER", "ADMIN");
                        auth.requestMatchers(HttpMethod.POST, "/account/**", "/student/**").hasRole("ADMIN");
                        auth.requestMatchers(HttpMethod.PUT, "/account/**", "/student/**").hasRole("ADMIN");
                        auth.requestMatchers(HttpMethod.DELETE, "/account/**", "/student/**").hasRole("ADMIN");
                        auth.anyRequest().authenticated();
                    })
                    .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                    //.httpBasic(Customizer.withDefaults())
                   // .oauth2Login(Customizer.withDefaults())
                    .build();
        }
}
