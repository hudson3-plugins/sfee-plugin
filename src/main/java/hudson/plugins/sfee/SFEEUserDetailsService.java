package hudson.plugins.sfee;

import hudson.plugins.sfee.webservice.ProjectSoapRow;
import hudson.plugins.sfee.webservice.UserSoapDO;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class SFEEUserDetailsService implements UserDetailsService {

	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException, DataAccessException {
		SourceForgeSite site = SourceForgeSite.DESCRIPTOR.getSite();
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
		authorities.add(new GrantedAuthorityImpl("authenticated"));

		String password = SFEESecurityRealm.DESCRIPTOR.getPassword(username);
		if (password == null) {
			throw new UsernameNotFoundException(
					"Password not known for this user - please login");
		}

		try {
			String sessionId = site.createSession(username, password);

			UserSoapDO userDetails = site.getUserDetails(username);
			if (userDetails.isSuperUser()) {
				authorities.add(new GrantedAuthorityImpl("admin"));
			}
			ProjectSoapRow[] projects = site.getProjects(sessionId);
			for (ProjectSoapRow project : projects) {
				authorities.add(new GrantedAuthorityImpl(project.getId()));
			}

			GrantedAuthority[] authoritiesArray = (GrantedAuthority[]) authorities
					.toArray(new GrantedAuthority[authorities.size()]);

			return new User(username, password, true, true, true, true,
					Arrays.asList(authoritiesArray));
		} catch (BadCredentialsException e) {
			throw e;
		} catch (Exception e) {
			throw new DataRetrievalFailureException("SFEE error", e);
		}
	}

}
