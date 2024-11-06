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

package be.nabu.eai.module.jwk;

import java.net.URI;
import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import be.nabu.eai.api.Advanced;
import be.nabu.eai.api.EnvironmentSpecific;
import be.nabu.eai.module.http.client.HTTPClientArtifact;
import be.nabu.eai.repository.api.CacheProviderArtifact;
import be.nabu.eai.repository.jaxb.ArtifactXMLAdapter;
import be.nabu.libs.types.api.annotation.Field;
import be.nabu.libs.types.base.Duration;

@XmlRootElement(name = "jwk")
public class JWKConfiguration {
	private List<URI> uris;
	// how long at least between resolving uris (to prevent DOS)
	// this defaults to 1 hour
	private Duration minimumRefreshDuration;
	private HTTPClientArtifact httpClient;
	private CacheProviderArtifact cacheProvider;
	// the very first jwk we pick up has an expiry date in 1994.......
	// the whole reason we adhere to the expiry date is to reset at an opportune time, we don't want to poll too often (dos) or too little (miss key rotation)
	// if the expiry date is in the past and stays there, it would open the door for DOS, we don't want that
	// by default it is not allowed and it will fall back to the minimum refresh duration
	private boolean allowExpiryInPast;
	
	public List<URI> getUris() {
		return uris;
	}
	public void setUris(List<URI> uris) {
		this.uris = uris;
	}
	public Duration getMinimumRefreshDuration() {
		return minimumRefreshDuration;
	}
	public void setMinimumRefreshDuration(Duration minimumRefreshDuration) {
		this.minimumRefreshDuration = minimumRefreshDuration;
	}
	
	@Field(comment = "You can opt for using a specific http client, for example if you are working with self-signed certificates for internal infrastructure. If left empty, the default http client will be used.")
	@Advanced
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public HTTPClientArtifact getHttpClient() {
		return httpClient;
	}
	public void setHttpClient(HTTPClientArtifact httpClient) {
		this.httpClient = httpClient;
	}
	
	@EnvironmentSpecific
	@XmlJavaTypeAdapter(value = ArtifactXMLAdapter.class)
	public CacheProviderArtifact getCacheProvider() {
		return cacheProvider;
	}
	public void setCacheProvider(CacheProviderArtifact cacheProvider) {
		this.cacheProvider = cacheProvider;
	}
	public boolean isAllowExpiryInPast() {
		return allowExpiryInPast;
	}
	public void setAllowExpiryInPast(boolean allowExpiryInPast) {
		this.allowExpiryInPast = allowExpiryInPast;
	}
	
}
