package be.nabu.eai.module.jwk;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

public class JWKEntry implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private Date expires;
	
	private Map<String, PublicKey> keys;

	public Date getExpires() {
		return expires;
	}

	public void setExpires(Date expires) {
		this.expires = expires;
	}

	public Map<String, PublicKey> getKeys() {
		return keys;
	}

	public void setKeys(Map<String, PublicKey> keys) {
		this.keys = keys;
	}
	
}
