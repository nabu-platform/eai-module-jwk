/*
* Copyright (C) 2022 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package nabu.security.jwk;

import java.io.IOException;
import java.net.URI;
import java.security.KeyStoreException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.validation.constraints.NotNull;

import be.nabu.eai.api.NamingConvention;
import be.nabu.eai.module.http.client.HTTPClientArtifact;
import be.nabu.eai.module.jwk.JWKArtifact;
import be.nabu.eai.repository.EAINode;
import be.nabu.eai.repository.EAIResourceRepository;
import be.nabu.eai.repository.api.CacheProviderArtifact;
import be.nabu.eai.repository.api.Entry;
import be.nabu.eai.repository.api.ModifiableEntry;
import be.nabu.eai.repository.resources.MemoryEntry;
import be.nabu.libs.http.jwt.JWTBody;
import be.nabu.libs.http.jwt.JWTUtils;
import be.nabu.libs.resources.memory.MemoryDirectory;
import be.nabu.libs.types.base.Duration;

@WebService
public class Services {
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@WebResult(name = "jwt")
	public JWTBody unmarshal(
			@WebParam(name = "jwkId") @NotNull String keystoreId, 
			@WebParam(name = "content") String content) throws KeyStoreException, IOException, ParseException {
		// if you don't have a "." in the name, it would have to be at the very root of the repository which is extremely unlikely and not well supported in general
		// so we assume you mean a dynamic collection at that point
		JWKArtifact jwk = resolve(keystoreId);
		if (jwk == null) {
			throw new IllegalArgumentException("Not a valid JWK artifact: " + keystoreId);
		}
		if (content != null) {
			Map keyMap = jwk.getKeyMap();
			return JWTUtils.decode(keyMap, content);
		}
		return null;
	}
	
	private JWKArtifact resolve(String id) {
		return (JWKArtifact) EAIResourceRepository.getInstance().resolve(id.indexOf('.') < 0 ? "nabu.security.jwk.dynamic." + NamingConvention.LOWER_CAMEL_CASE.apply(NamingConvention.UNDERSCORE.apply(id)) : id);
	}
	
	@WebResult(name = "keyIds")
	public List<String> keyIds(@WebParam(name = "jwkId") @NotNull String keystoreId) {
		JWKArtifact jwk = resolve(keystoreId);
		if (jwk == null) {
			throw new IllegalArgumentException("Not a valid JWK artifact: " + keystoreId);
		}
		return new ArrayList<String>(jwk.getKeyMap().keySet());
	}
	
	public void configureDynamic(
			@NotNull @WebParam(name = "collection") String collection, 
			@WebParam(name = "cacheId") String cacheId,
			@WebParam(name = "allowExpiryInPast") Boolean allowExpiryInPast,
			@WebParam(name = "minimumRefreshDuration") Duration minimumRefreshDuration,
			@WebParam(name = "httpClientId") String httpClientId,
			@NotNull @WebParam(name = "uris") List<URI> uris) throws IOException, ParseException {
		
		String collectionName = NamingConvention.LOWER_CAMEL_CASE.apply(NamingConvention.UNDERSCORE.apply(collection));
		String dynamicId = "nabu.security.jwk.dynamic";
		Entry dynamic = EAIResourceRepository.getInstance().getEntry(dynamicId);
		
		// make sure we have a dynamic entry
		if (dynamic == null) {
			Entry jwkEntry = EAIResourceRepository.getInstance().getEntry("nabu.security.jwk");
			dynamic = new MemoryEntry(jwkEntry.getRepository(), jwkEntry, null, dynamicId, dynamicId.replaceAll(".*?\\.([^.]+)$", "$1"));
			((ModifiableEntry) jwkEntry).addChildren(dynamic);
		}
		Entry jwkEntry = dynamic.getChild(collectionName);
		JWKArtifact jwkArtifact;
		if (jwkEntry == null) {
			EAINode node = new EAINode();
			jwkArtifact = new JWKArtifact(dynamicId + "." + collectionName, new MemoryDirectory(), dynamic.getRepository());
			node.setArtifactClass(jwkArtifact.getClass());
			node.setArtifact(jwkArtifact);
			node.setLeaf(true);
			jwkEntry = new MemoryEntry(dynamic.getRepository(), dynamic, node, jwkArtifact.getId(), collectionName);
			node.setEntry(jwkEntry);
			((ModifiableEntry) dynamic).addChildren(jwkEntry);
			// reset entry map so the new entries are picked up, e.g. for cache resets
			EAIResourceRepository.getInstance().resetEntryMap();
		}
		else {
			jwkArtifact = (JWKArtifact) jwkEntry.getNode().getArtifact();
		}
		// update the configuration
		jwkArtifact.getConfig().setCacheProvider(cacheId == null ? null : (CacheProviderArtifact) EAIResourceRepository.getInstance().resolve(cacheId));
		jwkArtifact.getConfig().setAllowExpiryInPast(allowExpiryInPast != null && allowExpiryInPast);
		jwkArtifact.getConfig().setMinimumRefreshDuration(minimumRefreshDuration);
		jwkArtifact.getConfig().setHttpClient(httpClientId == null ? null : (HTTPClientArtifact) EAIResourceRepository.getInstance().resolve(httpClientId));
		jwkArtifact.getConfig().setUris(uris);
		if (!jwkArtifact.isStarted()) {
			jwkArtifact.start();
		}
	}
}
