package be.nabu.eai.module.jwk;

import java.io.IOException;
import java.util.List;

import be.nabu.eai.developer.MainController;
import be.nabu.eai.developer.managers.base.BaseJAXBGUIManager;
import be.nabu.eai.repository.resources.RepositoryEntry;
import be.nabu.libs.property.api.Property;
import be.nabu.libs.property.api.Value;

public class JWKArtifactGUIManager extends BaseJAXBGUIManager<JWKConfiguration, JWKArtifact> {

	public JWKArtifactGUIManager() {
		super("JWK Keystore", JWKArtifact.class, new JWKArtifactManager(), JWKConfiguration.class);
	}

	@Override
	public String getCategory() {
		return "Security";
	}
	
	@Override
	protected List<Property<?>> getCreateProperties() {
		return null;
	}

	@Override
	protected JWKArtifact newInstance(MainController controller, RepositoryEntry entry, Value<?>... values) throws IOException {
		return new JWKArtifact(entry.getId(), entry.getContainer(), entry.getRepository());
	}

}
