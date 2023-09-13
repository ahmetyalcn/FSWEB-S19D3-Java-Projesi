package com.workintech.auth.util;

import lombok.Data;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Data
@Component
public class RsaKeyProperty {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public RsaKeyProperty() {
        KeyPair keyPair = KeyGeneratorUtility.generateRsaKeys();
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
    }
}
