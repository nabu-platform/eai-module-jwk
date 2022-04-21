package be.nabu.eai.module.jwk;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.nabu.eai.repository.RepositoryThreadFactory;
import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.artifacts.jaxb.JAXBArtifact;
import be.nabu.eai.repository.util.SystemPrincipal;
import be.nabu.libs.artifacts.api.StartableArtifact;
import be.nabu.libs.artifacts.api.StoppableArtifact;
import be.nabu.libs.cache.api.Cache;
import be.nabu.libs.cache.impl.AccessBasedTimeoutManager;
import be.nabu.libs.cache.impl.SerializableSerializer;
import be.nabu.libs.cache.impl.StringSerializer;
import be.nabu.libs.cache.memory.MemoryCache;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.api.client.HTTPClient;
import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.libs.http.core.HTTPUtils;
import be.nabu.libs.resources.ResourceUtils;
import be.nabu.libs.resources.api.ResourceContainer;
import be.nabu.libs.types.base.Duration;
import be.nabu.libs.types.binding.api.Window;
import be.nabu.libs.types.binding.json.JSONBinding;
import be.nabu.libs.types.map.MapContent;
import be.nabu.libs.types.map.MapTypeGenerator;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.mime.api.ContentPart;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.mime.impl.PlainMimeEmptyPart;
import be.nabu.utils.security.BCSecurityUtils;
import nabu.protocols.http.client.Services;

public class JWKArtifact extends JAXBArtifact<JWKConfiguration> implements StartableArtifact, StoppableArtifact {
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	private Cache cache;

	private Thread thread;
	
	// whether or not we want to poll the JWK periodically
	// the chance that we actually hit a timeout _before_ someone else triggers the timeout is very small
	// so it is most likely a useless feature unless you have very low volume jwk usage
	private boolean pollPeriodically = Boolean.parseBoolean(System.getProperty("jwk.poll", "false"));

	public JWKArtifact(String id, ResourceContainer<?> directory, Repository repository) {
		super(id, directory, repository, "jwk.xml", JWKConfiguration.class);
	}
	
	public Map<String, PublicKey> getKeyMap() {
		Map<String, PublicKey> keyMap = new HashMap<String, PublicKey>();
		List<URI> uris = getConfig().getUris();
		if (uris != null && !uris.isEmpty()) {
			for (URI uri : uris) {
				if (uri != null) {
					try {
						JWKEntry entry = loadJWK(uri, false);
						if (entry != null && entry.getKeys() != null) {
							keyMap.putAll(entry.getKeys());
						}
					}
					catch (IOException e) {
						logger.warn("Could not get keys for JWK url: " + uri, e);
					}
				}
			}
		}
		return keyMap;
	}

	// spec: https://datatracker.ietf.org/doc/html/rfc7517#page-6
	// note that if anything goes wrong (apart from cache storage), we will still store an empty entry with a timeout so we will try again later
	@SuppressWarnings("unused")
	public JWKEntry loadJWK(URI uri, boolean force) throws IOException {
		JWKEntry entry = cache == null ? null : (JWKEntry) cache.get(uri.toASCIIString());
		if (!force && entry != null) {
			if (entry.getExpires().after(new Date())) {
				logger.warn("Skipping jwk loading of '" + uri + "' because the last load is not expired yet");
				return entry;
			}
		}
		
		// if we are actually loading a JWK endpoint, we want to make sure we are loading it only once at the same time
		synchronized(this) {
			// recheck the cache, it may have been added by whoever had the lock
			entry = cache == null ? null : (JWKEntry) cache.get(uri.toASCIIString());
			if (!force && entry != null) {
				if (entry.getExpires().after(new Date())) {
					logger.warn("Skipping jwk loading of '" + uri + "' because the last load is not expired yet");
					return entry;
				}
			}
		
			logger.info("Loading JWK uri: " + uri + " / " + entry);
			
			// we reparse it into a new entry
			entry = new JWKEntry();
			
			ReadableContainer<ByteBuffer> readableContainer = null;
			
			// if you are using http (the default protocol), we can use the caching headers to reload the jwk at the optimal times to detect key rotation
			Date expires = null;
			try {
				if ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) {
					HTTPClient client = Services.getTransactionable(getRepository().newExecutionContext(SystemPrincipal.ROOT), null, getConfig().getHttpClient()).getClient();
					DefaultHTTPRequest request = new DefaultHTTPRequest("GET", uri.getPath(), new PlainMimeEmptyPart(null, 
							new MimeHeader("Content-Length", "0"),
							new MimeHeader("Host", uri.getHost())));
					HTTPResponse response = client.execute(request, null, "https".equalsIgnoreCase(uri.getScheme()), true);
					
					if (response.getCode() < 200 || response.getCode() >= 300) {
						throw new IllegalStateException("The endpoint '" + uri + "' responded with: [" + response.getCode() + "] " + response.getMessage());
					}
					
					if (response.getContent() instanceof ContentPart) {
						readableContainer = ((ContentPart) response.getContent()).getReadable();
					}
					else {
						throw new IllegalStateException("Could not find a response content on url: " + uri);
					}
					
					Header expiresHeader = MimeUtils.getHeader("Expires", response.getContent().getHeaders());
					if (expiresHeader != null) {
						try {
							logger.info("parsing expires: " + expiresHeader.getValue());
							expires = HTTPUtils.parseDate(expiresHeader.getValue());
						}
						catch (Exception e) {
							logger.error("Could not parse expiry date from uri '" + uri + "': " + expiresHeader.getValue(), e);
						}
					}
					if (expires == null) {
						Header cacheControlHeader = MimeUtils.getHeader("Cache-Control", response.getContent().getHeaders());
						if (cacheControlHeader != null) {
							try {
								String[] split = cacheControlHeader.getValue().split("[\\s]*,[\\s]*");
								for (String part : split) {
									if (part.startsWith("max-age")) {
										String[] split2 = part.split("[\\s]*=[\\s]*");
										if (split2.length == 2) {
											// in seconds
											long parsed = Long.parseLong(split2[1]);
											logger.info("parsed max age: " + parsed);
											expires = new Date(new Date().getTime() + (parsed * 1000));
										}
									}
								}
							}
							catch (Exception e) {
								logger.error("Could not parse cache control header from uri '" + uri + "': " + cacheControlHeader.getValue(), e);
							}
						}
					}
				}
				// you may want to load from file or the like
				else {
					readableContainer = ResourceUtils.toReadableContainer(uri, null);
				}
			}
			catch (Exception e) {
				logger.warn("Could not read JWK url: " + uri, e);
			}
			
			logger.info("expires1: " + expires);
			
			// we don't want expires in the past, we allow minimal leeway for slow responses etc at _very_ inopportune times or system clock synchronization
			// this still leaves a gap if a system would always respond with an expiry date max 1 min in the past, but that means the target system is doing very funky stuff
			if (!getConfig().isAllowExpiryInPast() && expires != null && expires.before(new Date(new Date().getTime() - 1l*60*1000))) {
				expires = null;
			}
			
			if (expires == null) {
				Duration minimumRefreshDuration = getConfig().getMinimumRefreshDuration();
				expires = new Date(new Date().getTime() + (minimumRefreshDuration == null ? 1000l * 60 * 60 * 60 : 1000l * minimumRefreshDuration.toSeconds())); 
			}
			
			logger.info("expires2: " + expires);
			entry.setExpires(expires);
			Map<String, PublicKey> keyMap = new HashMap<String, PublicKey>();
			entry.setKeys(keyMap);
			
			if (readableContainer != null) {
				try {
					JSONBinding binding = new JSONBinding(new MapTypeGenerator(true), Charset.forName("UTF-8"));
					binding.setAllowDynamicElements(true);
					binding.setAddDynamicElementDefinitions(true);
					binding.setAllowRaw(true);
					binding.setParseNumbers(true);
					binding.setSetEmptyArrays(true);
					MapContent content = (MapContent) binding.unmarshal(IOUtils.toInputStream(readableContainer), new Window[0]);
					/*
					 	{
							"keys": [
								{
									"kty": "RSA",
									"kid": "8OhRd2ceqZz44E6Rl7R1lqo9IzElbGywW5Qga3vSxM0",
									"use": "sig",
									"alg": "RS256",
									"n": "uueHmN8oT5zQ4EKI0GnrYzDfmlJApxuadvZX2CWOFPmUXIpefaizXvrHwhpr6go7HR1hznk1PeMOzx6XVnzNlwBUMHy_YoCHggQstQI05cJCpx3oogXskDIathGmWxufIs_xJEkSkj1S6_-Va2oFr3-oMY-W5h_tXAMxna6Zpwk2dzHnaptMg1C1yU0Z1RuDiBq1F0Xa5IhiSD-dEgaLrKDyMlzMqj7pDZlDnO7zXmzAr6Von8rQCmAnSp1pX8_8VF39nwy2J9eBeysz_bzQ-e8dqv1cPprAF-tiMMYyjisZd8gBdtO9Wb68-VL87UhPBUyWG7PLkSiwvQatQhOnPr0s_HLXns9xhISShQGyJU0CWN4hho4-J41Oa78mthaBWSgkrlp-56_vOTTIk12N-Iu7-FCRSejhD1IlCtWTBcjFK1ih2pwLss9eDv0Dj95MkKr1eIIKlRn0H1AQ179OCb3Kl4yZFnAgyZipT2KCKm8YmA-jyaOF6Lo7IWWzXDWefGW7wtExPJFE3QvfLvOeJNHpGUCC2JoRDoMp6KssdI26C9UzELgSCXzG5u7wUaz009Gw9dlT1VlI9YxWqeWTuR-vJY-AOpf2ds2vc9G7wDhLNOfoJotqoESpDDAOKNNN0qH2sq-DwfUQdfRBrnmfoGFHD7uZanXQ_3zfE3OIWds",
									"e": "AQAB"
								},
							]
						}
					 */
					
					List keys = (List) content.get("keys");
					for (Object key : keys) {
						if (key instanceof MapContent) {
							// e.g. RSA, EC
							// mandatory, case-sensitive
							String keyType = (String) ((MapContent) key).get("kty");
		
							// optional, e.g. "sig" (for signatures) or "enc" (for encryption)
							String usage = (String) ((MapContent) key).get("use");
							
							// optional, list of operations for which the key can be used, e.g. "sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"
							// key operations and usage "should not" be combined, if they _are_ combined, they must be consistent
							List keyOperations = (List) ((MapContent) key).get("key_ops");
							
							// optional, case sensitive
							String algorithm = (String) ((MapContent) key).get("alg");
		
							// optional, can be used to match the kid in the jwt header
							String keyId = (String) ((MapContent) key).get("kid");
							
							// a URL that can be used to resolve the chain which must be provided in pem format with specific delimiters for multiple (see spec)
							String x509Url = (String) ((MapContent) key).get("x5u");
							
							// a chain of base64 encoded certs that provide the chain
							List x509Chain = (List) ((MapContent) key).get("x5c");
							
							// sha-1 thumbprint, base64url encoded sha1 print of the der encoded x509 cert
							String x509Thumbprint = (String) ((MapContent) key).get("x5t");
							
							// same but sha-256
							String x509Thumbprint256 = (String) ((MapContent) key).get("x5t#S256");
							
							if (keyType.equalsIgnoreCase("RSA")) {
								// for public key
								String exponent = (String) ((MapContent) key).get("e");
								String modulus = (String) ((MapContent) key).get("n");
								
								// for private key
								String privateExponent = (String) ((MapContent) key).get("d");
								String firstPrime = (String) ((MapContent) key).get("p");
								String secondPrime = (String) ((MapContent) key).get("q");
								String firstFactorCRTExponent = (String) ((MapContent) key).get("dp");
								String secondFactorCRTExponent = (String) ((MapContent) key).get("dq");
								String firstCRTCoefficient = (String) ((MapContent) key).get("qi");
								
							}
							
							PublicKey publicKey = BCSecurityUtils.createJWKPublicKey(((MapContent) key).getContent());
							
							// generate a random one
							if (keyId == null) {
								keyId = "generated:" + UUID.randomUUID().toString().replace("-", "");
							}
							keyMap.put(keyId, publicKey);
						}
					}
				}
				catch (Exception e) {
					logger.warn("Could not parse JWK JSON", e);
				}
				finally {
					try {
						readableContainer.close();
					}
					catch (IOException e) {
						logger.debug("Could not close JWK readable", e);
					}
				}
			}
			
			if (cache != null) {
				logger.info("storing jwk using key: " + uri.toASCIIString());
				cache.put(uri.toASCIIString(), entry);
			}
			
			return entry;
		}
	}

	private boolean started;
	
	@Override
	public void start() throws IOException {
		started = true;
		AccessBasedTimeoutManager timeoutManager = new AccessBasedTimeoutManager(30l*24*60*60*1000);
		if (getConfiguration().getCacheProvider() != null) {
			cache = getConfiguration().getCacheProvider().create(getId(), 0, 0, new StringSerializer(), new SerializableSerializer(), null, timeoutManager);		
		}
//		else {
//			cache = new MemoryCache(null, timeoutManager);
//		}
		// need the correct context for deserializing
		RepositoryThreadFactory repositoryThreadFactory = new RepositoryThreadFactory(getRepository());
		thread = repositoryThreadFactory.newThread(new Runnable() {
			@Override
			public void run() {
				while (started) {
					getKeyMap();
					if (pollPeriodically) {
						try {
							Thread.sleep(30*60*1000l);
						}
						catch (InterruptedException e) {
							// continue
						}
					}
					else {
						break;
					}
				}
				thread = null;
			}
		});
		thread.setDaemon(true);
		thread.setName("jwk-loader-" + getId());
		thread.start();
	}

	@Override
	public boolean isStarted() {
		return started;
	}

	@Override
	public void stop() throws IOException {
		started = false;
		cache = null;
	}

}
