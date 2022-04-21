package nabu.security.jwk;

import java.io.IOException;
import java.security.KeyStoreException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.validation.constraints.NotNull;

import be.nabu.eai.module.jwk.JWKArtifact;
import be.nabu.eai.repository.EAIResourceRepository;
import be.nabu.libs.http.jwt.JWTBody;
import be.nabu.libs.http.jwt.JWTUtils;

@WebService
public class Services {
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@WebResult(name = "jwt")
	public JWTBody unmarshal(
			@WebParam(name = "jwkStoreId") @NotNull String keystoreId, 
			@WebParam(name = "content") String content) throws KeyStoreException, IOException, ParseException {
		JWKArtifact jwk = (JWKArtifact) EAIResourceRepository.getInstance().resolve(keystoreId);
		if (jwk == null) {
			throw new IllegalArgumentException("Not a valid JWK artifact: " + keystoreId);
		}
		if (content != null) {
			Map keyMap = jwk.getKeyMap();
			return JWTUtils.decode(keyMap, content);
		}
		return null;
	}
	
	@WebResult(name = "keyIds")
	public List<String> keyIds(@WebParam(name = "jwkStoreId") @NotNull String keystoreId) {
		JWKArtifact jwk = (JWKArtifact) EAIResourceRepository.getInstance().resolve(keystoreId);
		if (jwk == null) {
			throw new IllegalArgumentException("Not a valid JWK artifact: " + keystoreId);
		}
		return new ArrayList<String>(jwk.getKeyMap().keySet());
	}
}
