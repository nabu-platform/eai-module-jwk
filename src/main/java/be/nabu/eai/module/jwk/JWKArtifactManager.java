package be.nabu.eai.module.jwk;

import be.nabu.eai.repository.api.Repository;
import be.nabu.eai.repository.managers.base.JAXBArtifactManager;
import be.nabu.libs.resources.api.ResourceContainer;

public class JWKArtifactManager extends JAXBArtifactManager<JWKConfiguration, JWKArtifact> {

	public JWKArtifactManager() {
		super(JWKArtifact.class);
	}

	@Override
	protected JWKArtifact newInstance(String id, ResourceContainer<?> container, Repository repository) {
		return new JWKArtifact(id, container, repository);
	}

}
