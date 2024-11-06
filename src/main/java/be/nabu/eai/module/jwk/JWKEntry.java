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
