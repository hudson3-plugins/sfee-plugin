package hudson.plugins.sfee;

import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.model.Hudson;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.plugins.sfee.webservice.ArtifactDetailSoapList;
import hudson.plugins.sfee.webservice.ArtifactDetailSoapRow;
import hudson.plugins.sfee.webservice.CollabNetSoap;
import hudson.plugins.sfee.webservice.FileStorageAppSoap;
import hudson.plugins.sfee.webservice.FrsAppSoap;
import hudson.plugins.sfee.webservice.FrsFileSoapDO;
import hudson.plugins.sfee.webservice.FrsFileSoapList;
import hudson.plugins.sfee.webservice.FrsFileSoapRow;
import hudson.plugins.sfee.webservice.IllegalArgumentFault;
import hudson.plugins.sfee.webservice.InvalidFilterFault;
import hudson.plugins.sfee.webservice.InvalidSessionFault;
import hudson.plugins.sfee.webservice.NoSuchObjectFault;
import hudson.plugins.sfee.webservice.PackageSoapRow;
import hudson.plugins.sfee.webservice.PermissionDeniedFault;
import hudson.plugins.sfee.webservice.ProjectSoapRow;
import hudson.plugins.sfee.webservice.ReleaseSoapDO;
import hudson.plugins.sfee.webservice.ReleaseSoapList;
import hudson.plugins.sfee.webservice.ReleaseSoapRow;
import hudson.plugins.sfee.webservice.SearchQuerySyntaxFault;
import hudson.plugins.sfee.webservice.SystemFault;
import hudson.plugins.sfee.webservice.TrackerAppSoap;
import hudson.plugins.sfee.webservice.TrackerSoapRow;
import hudson.plugins.sfee.webservice.UserSoapDO;
import hudson.plugins.sfee.webservice.UserSoapRow;
import hudson.plugins.sfee.webservice.VersionMismatchFault;

import java.io.Serializable;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

import javax.activation.DataHandler;

import net.sf.json.JSONObject;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

public class SourceForgeSite extends JobProperty<AbstractProject<?, ?>>
		implements Serializable {

	private transient FrsAppSoap frsApp;
	private transient CollabNetSoap sfApp;

	private long lastSessionRequest;

	/**
	 * URL of JIRA, like <tt>http://jira.codehaus.org/</tt>. Mandatory.
	 * Normalized to end with '/'
	 */
	private String site;

	/**
	 * User name needed to login. Optional.
	 */
	private String userName;

	/**
	 * Password needed to login. Optional.
	 */
	private String password;

	private transient String sessionId;
	private transient TrackerAppSoap trackerApp;

	@Extension
	public static final DescriptorImpl DESCRIPTOR = new DescriptorImpl();

	@DataBoundConstructor
	public SourceForgeSite(String site, String userName, String password) {
		this.site = site;
		this.userName = Util.fixEmpty(userName);
		this.password = Util.fixEmpty(password);
	}

	public SourceForgeSite() {
	}

	public String getSite() {
		return site;
	}

	private ProjectSoapRow[] projects;
	private long lastProjectsUpdate;

	/**
	 * returns all projects
	 * 
	 * @return
	 */
	public synchronized ProjectSoapRow[] getProjects() {
		if (sessionId == null
				|| (System.currentTimeMillis() - lastProjectsUpdate > 15000)) {
			projects = SFEE.getProjects(getSessionId(), site);
			lastProjectsUpdate = System.currentTimeMillis();
		}
		return projects;
	}

	public synchronized String getSessionId() {
		if (sessionId == null
				|| (System.currentTimeMillis() - lastSessionRequest > 15000)) {
			sessionId = SFEE.createSession(site, userName, password);
			lastSessionRequest = System.currentTimeMillis();
		}

		return sessionId;
	}

	@Override
	public JobPropertyDescriptor getDescriptor() {
		return SourceForgeSite.DESCRIPTOR;
	}

	public static final class DescriptorImpl extends JobPropertyDescriptor {

		private SourceForgeSite site;

		protected DescriptorImpl() {
			super(SourceForgeSite.class);
			load();
		}

		@Override
		public String getDisplayName() {
			return "SFEE";
		}

		@Override
		public boolean isApplicable(Class<? extends Job> klazz) {
			return Hudson.class.isAssignableFrom(klazz);
		}

		@Override
		public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
			site = req.bindParameters(SourceForgeSite.class, "sfee.");
			save();
			return true;
		}

		public SourceForgeSite getSite() {
			return site;
		}

		public void setSite(SourceForgeSite site) {
			this.site = site;
		}
	}

	public FrsAppSoap getFrsApp() {
		if (frsApp == null) {
			frsApp = SFEE.getCollabNetApp(site, FrsAppSoap.class);

		}
		return frsApp;
	}

	public CollabNetSoap getSfApp() {
		if (sfApp == null) {
			sfApp = SFEE.getCollabNetApp(site, CollabNetSoap.class);
		}
		return sfApp;
	}

	public TrackerAppSoap getTrackerApp() {
		if (trackerApp == null) {
			trackerApp = SFEE.getCollabNetApp(site, TrackerAppSoap.class);
		}
		return trackerApp;
	}

	public String getURL(String artifactId) {
		return String.format("http://%s/sf/go/%s", site, artifactId);
	}

	public FileStorageAppSoap getFileStorageApp() {
		return SFEE.getCollabNetApp(site, FileStorageAppSoap.class);
	}

	/**
	 * Updates the title of the release with the given name.
	 * 
	 * @return the id of the release that was changed, or null is no such
	 *         release
	 * @throws RemoteException
	 * @throws PermissionDeniedFault
	 * @throws SystemFault
	 * @throws InvalidSessionFault
	 * @throws NoSuchObjectFault
	 */
	public String updateReleaseName(String packageId, String oldName,
			String newName) throws NoSuchObjectFault, InvalidSessionFault,
			SystemFault, PermissionDeniedFault, RemoteException {
		FrsAppSoap frsApp = getFrsApp();
		String sessionId = getSessionId();
		ReleaseSoapList existingReleases = frsApp.getReleaseList(sessionId,
				packageId);
		for (ReleaseSoapRow row : existingReleases.getDataRows()) {
			if (oldName.equals(row.getTitle())) {
				String releaseId = row.getId();
				ReleaseSoapDO releaseToReplace = frsApp.getReleaseData(
						sessionId, releaseId);
				releaseToReplace.setTitle(newName);
				frsApp.setReleaseData(sessionId, releaseToReplace);
				return releaseId;
			}
		}

		return null;
	}

	/**
	 * Updates the title of the release with the given name.
	 * 
	 * @return the id of the release that was changed, or null is no such
	 *         release
	 * @throws RemoteException
	 * @throws PermissionDeniedFault
	 * @throws SystemFault
	 * @throws InvalidSessionFault
	 * @throws NoSuchObjectFault
	 */
	public String getReleaseId(String packageId, String name)
			throws NoSuchObjectFault, InvalidSessionFault, SystemFault,
			PermissionDeniedFault, RemoteException {
		String releaseId = null;
		FrsAppSoap frsApp = getFrsApp();
		String sessionId = getSessionId();

		ReleaseSoapList existingReleases = frsApp.getReleaseList(sessionId,
				packageId);

		for (ReleaseSoapRow row : existingReleases.getDataRows()) {
			if (name.equals(row.getTitle())) {
				releaseId = row.getId();
				break;
			}
		}

		return releaseId;
	}

	public List<ArtifactDetailSoapRow> findArtifactsResolvedInRelease(
			String releaseTitle, String projectId) throws InvalidFilterFault,
			NoSuchObjectFault, InvalidSessionFault, SystemFault,
			PermissionDeniedFault, RemoteException {
		List<ArtifactDetailSoapRow> result = new ArrayList<ArtifactDetailSoapRow>();
		String sessionId = getSessionId();

		TrackerAppSoap trackerApp = getTrackerApp();

		for (TrackerSoapRow trackerRow : getTrackers(projectId)) {
			ArtifactDetailSoapList artifactDetailList = trackerApp
					.getArtifactDetailList(sessionId, trackerRow.getId(), null, null, null, 0, -1, false, true);

			for (ArtifactDetailSoapRow row : artifactDetailList.getDataRows()) {
				if (releaseTitle.equals(row.getResolvedInReleaseTitle())) {
					result.add(row);
				}
			}
		}
		return result;
	}

	public String createRelease(String packageId, String releaseName,
			String description, String status, String maturity)
			throws IllegalArgumentFault, NoSuchObjectFault,
			InvalidSessionFault, SystemFault, PermissionDeniedFault,
			RemoteException {
		FrsAppSoap frsApp = getFrsApp();
		String sessionId = getSessionId();
		ReleaseSoapDO release = frsApp.createRelease(sessionId, packageId,
				releaseName, description, status, maturity);
		return release.getId();
	}

	public String getFrsId(String releaseId, String fileName)
			throws InvalidSessionFault, SystemFault, RemoteException {
		String ret = null;
		String sessionId = getSessionId();
		FrsAppSoap frsApp = getFrsApp();

		FrsFileSoapList fileSoapList = frsApp.getFrsFileList(sessionId,
				releaseId);

		for (FrsFileSoapRow row : fileSoapList.getDataRows()) {
			if (fileName.equals(row.getFilename())) {
				ret = row.getId();
				break;
			}
		}

		return ret;
	}

	public String uploadFileForRelease(String releaseId, String name,
			URL sourceURL, boolean forceUpdate) throws InvalidSessionFault,
			SystemFault, RemoteException {
		return uploadFileForRelease(releaseId, name,
				new DataHandler(sourceURL), forceUpdate);
	}

	public String uploadFileForRelease(String releaseId, String name,
			DataHandler dataHandler, boolean forceUpdate)
			throws InvalidSessionFault, SystemFault, RemoteException {
		String sessionId = getSessionId();
		FileStorageAppSoap fileApp = getFileStorageApp();
		String fileId = fileApp.uploadFile(sessionId, dataHandler);

		if (forceUpdate) {
			String frsId = getFrsId(releaseId, name);

			if (frsId != null) {
				getFrsApp().deleteFrsFile(sessionId, frsId);
			}
		}

		FrsFileSoapDO frsFile = getFrsApp().createFrsFile(sessionId, releaseId,
				name, dataHandler.getContentType(), fileId);
		return frsFile.getId();
	}

	public PackageSoapRow[] getReleasePackages(String projectId)
			throws NoSuchObjectFault, InvalidSessionFault, SystemFault,
			PermissionDeniedFault, RemoteException {
		return getFrsApp().getPackageList(getSessionId(), projectId)
				.getDataRows();
	}

	public TrackerSoapRow[] getTrackers(String projectId)
			throws NoSuchObjectFault, InvalidSessionFault, SystemFault,
			PermissionDeniedFault, RemoteException {
		return getTrackerApp().getTrackerList(getSessionId(), projectId)
				.getDataRows();
	}

	public UserSoapRow[] getUsers() throws SearchQuerySyntaxFault,
			IllegalArgumentFault, InvalidSessionFault, SystemFault,
			PermissionDeniedFault, RemoteException {
		return getSfApp().getUserList(getSessionId(), null).getDataRows();
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String createSession(String userName, String password) {
		return SFEE.createSession(site, userName, password);
	}

	public UserSoapDO getUserDetails(String username)
			throws InvalidSessionFault, NoSuchObjectFault,
			IllegalArgumentFault, RemoteException {
		return getSfApp().getUserData(getSessionId(), username);
	}

	/**
	 * returns projects for user logged in with this session id
	 * 
	 * @param sessionId
	 * @return
	 * @throws RemoteException
	 * @throws SystemFault
	 * @throws InvalidSessionFault
	 */
	public ProjectSoapRow[] getProjects(String sessionId)
			throws InvalidSessionFault, SystemFault, RemoteException {
		return getSfApp().getUserProjectList(sessionId).getDataRows();
	}

	public void updateRelease(String releaseId, String maturity, String status)
			throws NoSuchObjectFault, InvalidSessionFault, SystemFault,
			PermissionDeniedFault, RemoteException {
		FrsAppSoap frsApp = getFrsApp();
		String sessionId = getSessionId();
		ReleaseSoapDO releaseData = frsApp.getReleaseData(sessionId, releaseId);
		if (maturity != null) {
			releaseData.setMaturity(maturity);
		}
		if (status != null) {
			releaseData.setStatus(status);
		}
		frsApp.setReleaseData(sessionId, releaseData);
	}

	public void obsoleteRelease(String releaseId) throws VersionMismatchFault,
			IllegalArgumentFault, NoSuchObjectFault, InvalidSessionFault,
			SystemFault, PermissionDeniedFault, RemoteException {
		FrsAppSoap frsApp = getFrsApp();
		String sessionId = getSessionId();
		ReleaseSoapDO releaseData = frsApp.getReleaseData(sessionId, releaseId);
		releaseData.setMaturity("Obsolete");
		releaseData.setTitle("[obsolete] " + releaseData.getTitle());
		frsApp.setReleaseData(sessionId, releaseData);
	}

}
