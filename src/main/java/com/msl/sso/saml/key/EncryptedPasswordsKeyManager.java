package com.msl.sso.saml.key;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.opensaml.common.SAMLRuntimeException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;

import com.msl.sso.saml.dao.impl.SAMLPasswordDAO;

public class EncryptedPasswordsKeyManager implements KeyManager {
    
    @Autowired
    private SAMLPasswordDAO samlPasswordDAO;
    
    private final Logger log = LoggerFactory.getLogger(JKSKeyManager.class);

    private CredentialResolver credentialResolver;
    private KeyStore keyStore;
    private Set<String> availableKeys;
    private String defaultKey;

    private Resource storeFile;
    private String storePass;
    private Map<String, String> passwords;  
    
    /**
     * Default constructor which uses an existing KeyStore instance for loading of credentials. Available keys are
     * calculated automatically.
     *
     * @param keyStore key store to use
     * @param passwords passwords used to access private keys
     * @param defaultKey default key
     */
    public EncryptedPasswordsKeyManager(KeyStore keyStore, Map<String, String> passwords, String defaultKey) {
        this.keyStore = keyStore;
        this.availableKeys = getAvailableKeys(keyStore);
        this.credentialResolver = new KeyStoreCredentialResolver(keyStore, passwords);
        this.defaultKey = defaultKey;
    }

    /**
     * Default constructor which instantiates a new KeyStore used to load all credentials. Available keys are
     * calculated automatically.
     *
     * @param storeFile file pointing to the JKS keystore
     * @param storePass password to access the keystore, or null for no password
     * @param passwords passwords used to access private keys
     * @param defaultKey default key
     */
    public EncryptedPasswordsKeyManager(Resource storeFile, String storePass, Map<String, String> passwords, String defaultKey) {
        this.storeFile = storeFile;
        this.storePass = storePass;
        this.passwords = passwords;
        //Init null forcing not validating credentials
        this.keyStore = null;        
        this.availableKeys = null;        
        this.credentialResolver = null;
        this.defaultKey = defaultKey;        
    }

    /**
     * Loads all aliases available in the keyStore.
     *
     * @param keyStore key store to load aliases from
     * @return aliases
     */
    private Set<String> getAvailableKeys(KeyStore keyStore) {
        try {
            Set<String> availableKeys = new HashSet<String>();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                availableKeys.add(aliases.nextElement());
            }
            return availableKeys;
        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to load aliases from keyStore", e);
        }
    }

    /**
     * Initializes the keystore using given properties.
     *
     * @param storeFile file pointing to the JKS keystore
     * @param storePass password to open the keystore, or null for no password
     * @param storeType type of keystore
     * @return initialized key store
     */
    private KeyStore initialize(Resource storeFile, String storePass, String storeType) {
        InputStream inputStream = null;
        try {
            inputStream = storeFile.getInputStream();
            KeyStore ks = KeyStore.getInstance(storeType);
            ks.load(inputStream, storePass == null ? null : storePass.toCharArray());
            return ks;
        } catch (Exception e) {
            log.error("Error initializing key store", e);
            throw new RuntimeException("Error initializing keystore", e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    log.debug("Error closing input stream for keystore.", e);
                }
            }
        }
    }

    /**
     * Returns certificate with the given alias from the keystore.
     *
     * @param alias alias of certificate to find
     * @return certificate with the given alias or null if not found
     */
    public X509Certificate getCertificate(String alias) {
        if (alias == null || alias.length() == 0) {
            return null;
        }
        try {
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (Exception e) {
            log.error("Error loading certificate", e);
        }
        return null;
    }

    /**
     * Returns public key with the given alias
     *
     * @param alias alias of the key to find
     * @return public key of the alias or null if not found
     */
    public PublicKey getPublicKey(String alias) {
        X509Certificate x509Certificate = getCertificate(alias);
        if (x509Certificate != null) {
            return x509Certificate.getPublicKey();
        } else {
            return null;
        }
    }

    public Iterable<Credential> resolve(CriteriaSet criteriaSet) throws org.opensaml.xml.security.SecurityException {
        return credentialResolver.resolve(criteriaSet);
    }

    public Credential resolveSingle(CriteriaSet criteriaSet) throws SecurityException {
        return credentialResolver.resolveSingle(criteriaSet);
    }

    /**
     * Returns Credential object used to sign the messages issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @param keyName name of the key to use, in case of null default key is used
     * @return credential
     */
    public Credential getCredential(String keyName) {

        if (keyName == null) {
            keyName = defaultKey;
        }

        try {
            CriteriaSet cs = new CriteriaSet();
            EntityIDCriteria criteria = new EntityIDCriteria(keyName);
            cs.add(criteria);
            return resolveSingle(cs);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new SAMLRuntimeException("Can't obtain SP signing key", e);
        }

    }

    /**
     * Returns Credential object used to sign the messages issued by this entity.
     * Public, X509 and Private keys are set in the credential.
     *
     * @return credential
     */
    public Credential getDefaultCredential() {
        return getCredential(null);
    }

    public String getDefaultCredentialName() {
        return defaultKey;
    }
    
    public KeyStore getKeyStore() {
        return keyStore;
    }  

    public Set<String> getAvailableCredentials() {
        if (null==availableKeys){
            
           SAMLPasswordCipher decripter = new SAMLPasswordCipher();

            String storePassDecrypted = obtainDBKeyValue(this.storePass);                 
            storePassDecrypted = decripter.decrypt(storePassDecrypted);
            this.keyStore = initialize(this.storeFile, storePassDecrypted, "JKS");
            
            this.availableKeys = getAvailableKeys(this.keyStore);
            
            String credentialPassDecrypted = obtainDBKeyValue(this.passwords.get(defaultKey));
            credentialPassDecrypted = decripter.decrypt(credentialPassDecrypted);
            this.passwords.put(defaultKey, credentialPassDecrypted);
            
            this.credentialResolver = new KeyStoreCredentialResolver(this.keyStore, this.passwords);
        }
        return availableKeys;
    }
 
    public String obtainDBKeyValue(String key) {        
        String passValue=null;
        passValue = samlPasswordDAO.getValue(key);        
        return passValue;
    }
}
