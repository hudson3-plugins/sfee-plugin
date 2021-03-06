package hudson.plugins.sfee;

import hudson.Util;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BallColor;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskAction;
import hudson.model.TaskListener;
import hudson.model.TaskThread;
import hudson.model.TaskThread.ListenerAndText;
import hudson.plugins.sfee.webservice.ArtifactDetailSoapRow;
import hudson.plugins.sfee.webservice.InvalidFilterFault;
import hudson.plugins.sfee.webservice.InvalidSessionFault;
import hudson.plugins.sfee.webservice.NoSuchObjectFault;
import hudson.plugins.sfee.webservice.PermissionDeniedFault;
import hudson.plugins.sfee.webservice.SystemFault;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import hudson.util.Iterators;
import hudson.widgets.HistoryWidget;
import hudson.widgets.HistoryWidget.Adapter;

import java.io.File;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.servlet.ServletException;

import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.framework.io.LargeText;

public class SFEEReleaseTask<T extends AbstractBuild> extends TaskAction
		implements AccessControlled {

	private final AbstractBuild<?, ?> build;

	private final String releasePackageId;
	private final String releaseName;
	private final String maturity;
	private final String releaseToReplace;
	private List<TrackerArtifact> resolvedTrackerArtifacts;

	private final boolean uploadFiles;
	private final boolean replaceFiles;

	private boolean uploadBuildLog;
	private Map<String, Boolean> downloadingArtifactList = null;

	public SFEEReleaseTask(AbstractBuild<?, ?> build, String releasePackageId,
			String releaseName, String releaseToReplace, String maturity,
			boolean uploadFiles, boolean replaceFiles) {
		this.build = build;
		this.releasePackageId = releasePackageId;
		this.releaseName = releaseName;
		this.releaseToReplace = releaseToReplace;
		this.maturity = maturity;
		this.uploadFiles = uploadFiles;
		this.replaceFiles = replaceFiles;
	}

	@Override
	public ACL getACL() {
		return build.getACL();
	}

	@Override
	protected Permission getPermission() {
		return PluginImpl.PUBLISH;
	}

	public String getDisplayName() {
		if (hasPermission(getPermission())) {
			return "SourceForge";
		} else {
			return null;
		}
	}

	public String getIconFileName() {
		if (hasPermission(getPermission())) {
			return isCompleted() ? "star-gold.gif" : "star.gif";
		} else {
			return null;
		}
	}

	public String getUrlName() {
		if (hasPermission(getPermission())) {
			return "upload";
		} else {
			return null;
		}
	}

	public boolean isCompleted() {
		return records.size() > 0
				&& records.get(records.size() - 1).getResult() == Result.SUCCESS;
	}

	/**
	 * Records of a deployment.
	 */
	public final CopyOnWriteArrayList<Record> records = new CopyOnWriteArrayList<Record>();

	protected String fileReleaseId;

	public HistoryWidgetImpl getHistoryWidget() {
		return new HistoryWidgetImpl();
	}

	public Object getDynamic(String token, StaplerRequest req,
			StaplerResponse rsp) {
		if ("buildHistory".equals(token)) {
			return getHistoryWidget();
		}

		if ("buildTimeTrend".equals(token)) {
			return null;
		}

		return records.get(Integer.valueOf(token));
	}

	private final class HistoryWidgetImpl extends
			HistoryWidget<SFEEReleaseTask<?>, Record> {
		private HistoryWidgetImpl() {
			super(SFEEReleaseTask.this, Iterators.reverse(records), ADAPTER);
		}

		@Override
		public String getDisplayName() {
			return "Deployment History";
		}
	}

	/**
	 * Performs an upload.
	 */
	public final void doUpload(StaplerRequest req, StaplerResponse rsp)
			throws ServletException, IOException {
		getACL().checkPermission(getPermission());

		// ----------------------------------
		// Check upload of build log
		// ----------------------------------
		uploadBuildLog = "on".equals(req.getParameter("uploadBuildLog"));

		// ----------------------------------
		// Set which artifact to upload
		// ----------------------------------
		boolean doUpload = false;

		List buildArtifacts = build.getArtifacts();

		for (Iterator iterator = buildArtifacts.iterator(); iterator.hasNext();) {

			Run.Artifact buildArtifact = (Run.Artifact) iterator.next();

			doUpload = "on".equals(req
					.getParameter(buildArtifact.getFileName()));

			getDownloadingArtifactList().put(buildArtifact.getFileName(),
					doUpload);
		}

		startUpload();

		rsp.sendRedirect(".");
	}

	public void startUpload() throws IOException {
		File logFile = new File(build.getRootDir(), "sfee-upload."
				+ records.size() + ".log");
		final Record record = new Record(logFile.getName());
		records.add(record);

		new TaskThread(this, ListenerAndText.forFile(logFile)) {
			protected void perform(TaskListener listener) throws Exception {
				try {
					long start = System.currentTimeMillis();

					final SourceForgeSite site = SourceForgeSite.DESCRIPTOR
							.getSite();

					if (fileReleaseId == null) {

						fileReleaseId = createOrUpdateRelease(listener,
								releaseName, releaseToReplace,
								releasePackageId, maturity);
						if (fileReleaseId == null) {
							record.result = Result.FAILURE;
							return;
						}

						if (isUploadFiles()) {
							listener.getLogger().println(
									"Existing files will "
											+ (isReplaceFiles() ? "" : "not")
											+ " be overwitten");

							if (isUploadBuildLog()) {
								String logFileName = releaseName + "-"
										+ build.getParent().getDisplayName()
										+ "-" + build.getNumber() + "-"
										+ build.getId() + ".log";
								listener.getLogger().println(
										"Uploading build log file "
												+ logFileName + "...");

								site.uploadFileForRelease(fileReleaseId,
										logFileName, new DataHandler(
												new FileDataSource(build
														.getLogFile())),
										isReplaceFiles());
							}

							List buildArtifacts = build.getArtifacts();

							for (Iterator iterator = buildArtifacts.iterator(); iterator
									.hasNext();) {
								Run.Artifact buildArtifact = (Run.Artifact) iterator
										.next();

								if (getDownloadingArtifactList().get(
										buildArtifact.getFileName())) {
									listener.getLogger().print(
											"Uploading file "
													+ buildArtifact
															.getFileName()
													+ " ...");

									site.uploadFileForRelease(fileReleaseId,
											buildArtifact.getFileName(),
											buildArtifact.getFile().toURI().toURL(),
											isReplaceFiles());

									listener.getLogger().println(
											" upload successfully completed!");
								} else {
									listener.getLogger().println(
											"Skipping unselected file "
													+ buildArtifact
															.getFileName());
								}
							}
						}
					} else {
						listener.getLogger().println(
								"Reusing previous release " + fileReleaseId);
					}

					resolvedTrackerArtifacts = findResolvedArtifacts(build
							.getProject(), releaseName);

					long duration = System.currentTimeMillis() - start;

					listener.getLogger().println(
							"Total time: " + Util.getTimeSpanString(duration));

					record.result = Result.SUCCESS;

					build.addAction(new SFEEReleaseCompletedTask(
							SFEEReleaseTask.this));

					onComplete();

				} finally {
					if (record.result == null)
						record.result = Result.FAILURE;
					// persist the record
					build.save();
				}
			}
		}.start();
	}

	private static final Adapter<SFEEReleaseTask.Record> ADAPTER = new Adapter<SFEEReleaseTask.Record>() {
		public int compare(SFEEReleaseTask.Record record, String key) {
			return record.getNumber() - Integer.parseInt(key);
		}

		public String getKey(SFEEReleaseTask.Record record) {
			return String.valueOf(record.getNumber());
		}

		public boolean isBuilding(SFEEReleaseTask.Record record) {
			return record.isBuilding();
		}

		public String getNextKey(String key) {
			return String.valueOf(Integer.parseInt(key) + 1);
		}
	};

	public final class Record {
		/**
		 * Log file name. Relative to {@link AbstractBuild#getRootDir()}.
		 */
		private final String fileName;

		/**
		 * Status of this record.
		 */
		private Result result;

		private final Calendar timeStamp;

		private long duration, estimatedDuration;

		public Record(String fileName) {
			this.fileName = fileName;
			timeStamp = new GregorianCalendar();
		}

		/**
		 * Returns the log of this deployment record.
		 */
		public LargeText getLog() {
			return new LargeText(new File(build.getRootDir(), fileName), true);
		}

		/**
		 * Result of the deployment. During the build, this value is null.
		 */
		public Result getResult() {
			return result;
		}

		public int getNumber() {
			return records.indexOf(this);
		}

		public boolean isBuilding() {
			return result == null;
		}

		public Calendar getTimestamp() {
			return (Calendar) timeStamp.clone();
		}

		public String getBuildStatusUrl() {
			return getIconColor().getImage();
		}

		public BallColor getIconColor() {
			if (result == null)
				return BallColor.GREY_ANIME;
			else
				return result.color;
		}

		// TODO: Eventually provide a better UI
		public final void doIndex(StaplerRequest req, StaplerResponse rsp)
				throws IOException {
			rsp.setContentType("text/plain;charset=UTF-8");
			getLog().writeLogTo(0, rsp.getWriter());
		}

		public void doStop(StaplerRequest req, StaplerResponse rsp)
				throws IOException {
			rsp.sendRedirect("../stop");
		}

		public String getTimestampString() {
			return Util.getTimeSpanString(duration);
		}

		public Object getExecutor() {
			return new Object() {
				/**
				 * Returns the progress of the current build in the number
				 * between 0-100.
				 * 
				 * @return -1 if it's impossible to estimate the progress.
				 */
				public int getProgress() {
					long d = estimatedDuration;
					if (d < 0)
						return -1;

					int num = (int) ((System.currentTimeMillis() - timeStamp
							.getTimeInMillis()) * 100 / d);
					if (num >= 100)
						num = 99;
					return num;
				}
			};
		}
	}

	public static String createOrUpdateRelease(TaskListener listener,
			String releaseName, String releaseToReplace, String packageId,
			String maturity) throws NoSuchObjectFault, InvalidSessionFault,
			SystemFault, PermissionDeniedFault, RemoteException {
		final SourceForgeSite site = SourceForgeSite.DESCRIPTOR.getSite();

		String releaseId = null;

		if (releaseToReplace != null) {
			listener.getLogger().printf(
					"Update release from '%s' to '%s'\n...", releaseToReplace,
					releaseName);
			// update old release
			releaseId = site.updateReleaseName(packageId, releaseToReplace,
					releaseName);
			if (releaseId == null) {
				listener.fatalError("No release found with name "
						+ releaseToReplace);
				return null;
			}
			// creating next release
			listener.getLogger().printf("Creating new release '%s'\n",
					releaseToReplace);
			site.createRelease(packageId, releaseToReplace, "", "active",
					maturity);
		} else {
			// create release
			listener.getLogger().printf("Checking for existing release\n",
					releaseName);

			releaseId = site.getReleaseId(packageId, releaseName);

			if (releaseId == null) {
				listener.getLogger().printf("Creating new release '%s'\n",
						releaseName);

				releaseId = site.createRelease(packageId, releaseName, "",
						"active", maturity);
			}
		}

		return releaseId;

	}

	private List<TrackerArtifact> findResolvedArtifacts(
			AbstractProject<?, ?> p, String releaseName)
			throws InvalidFilterFault, NoSuchObjectFault, InvalidSessionFault,
			SystemFault, PermissionDeniedFault, RemoteException {
		SourceForgeProject project = SourceForgeProject.getProperty(p);
		SourceForgeSite site = SourceForgeSite.DESCRIPTOR.getSite();

		List<ArtifactDetailSoapRow> findArtifactsResolvedInRelease = site
				.findArtifactsResolvedInRelease(releaseName, project
						.getProjectId());

		List<TrackerArtifact> trackerArtifacts = new ArrayList<TrackerArtifact>();
		for (ArtifactDetailSoapRow r : findArtifactsResolvedInRelease) {
			System.out.println("Adding new TrackerArtifact");
			trackerArtifacts.add(new TrackerArtifact(r));
		}

		System.out.println("TrackerArtifact size: " + trackerArtifacts.size());

		return trackerArtifacts;
	}

	public AbstractBuild<?, ?> getBuild() {
		return build;
	}

	public String getReleasePackageId() {
		return releasePackageId;
	}

	public String getReleaseName() {
		return releaseName;
	}

	public String getMaturity() {
		return maturity;
	}

	public String getReleaseToReplace() {
		return releaseToReplace;
	}

	public List<TrackerArtifact> getResolvedTrackerArtifacts() {
		try {
			resolvedTrackerArtifacts = findResolvedArtifacts(
					build.getProject(), releaseName);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return resolvedTrackerArtifacts;
	}

	public boolean isUploadFiles() {
		return uploadFiles;
	}

	public boolean isReplaceFiles() {
		return replaceFiles;
	}

	public CopyOnWriteArrayList<Record> getRecords() {
		return records;
	}

	public Object getFileReleaseId() {
		return fileReleaseId;
	}

	public String getFileReleaseUrl() {
		return fileReleaseId != null ? SourceForgeSite.DESCRIPTOR.getSite()
				.getURL(fileReleaseId) : null;
	}

	public boolean isUploadBuildLog() {
		return uploadBuildLog;
	}

	public void setUploadBuildLog(boolean uploadBuildLog) {
		this.uploadBuildLog = uploadBuildLog;
	}

	public void doStop(StaplerRequest req, StaplerResponse rsp)
			throws IOException {
		if (workerThread != null) {
			workerThread.interrupt();
		}
		rsp.sendRedirect(".");
	}

	protected void onComplete() {
	}

	public void setDownloadingArtifactList(
			Map<String, Boolean> downloadingArtifactList) {
		this.downloadingArtifactList = downloadingArtifactList;
	}

	public Map<String, Boolean> getDownloadingArtifactList() {
		if (downloadingArtifactList == null) {
			downloadingArtifactList = new HashMap<String, Boolean>();

			List buildArtifacts = build.getArtifacts();

			for (Iterator iterator = buildArtifacts.iterator(); iterator
					.hasNext();) {

				Run.Artifact buildArtifact = (Run.Artifact) iterator.next();

				System.out.println("Adding new artifact: "
						+ buildArtifact.getFileName());
				downloadingArtifactList.put(buildArtifact.getFileName(),
						Boolean.TRUE);
			}
		}
		return downloadingArtifactList;
	}

	public void checkPermission(Permission permission) {
		getACL().checkPermission(permission);
	}

	public boolean hasPermission(Permission permission) {
		return getACL().hasPermission(permission);
	}

}
