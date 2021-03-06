package hudson.plugins.sfee;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Descriptor;
import hudson.plugins.descriptionsetter.DescriptionSetterAction;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.sf.json.JSONObject;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

public class SFEEReleasePublisher extends Notifier {

	private static final String REGEXP = ".*\\[INFO\\] Uploading project information for "
			+ "[^\\s]* ([^\\s]*)";

	private final String releaseToReplace;
	private final boolean uploadArtifacts = true;
	private final String maturity;
	private final boolean uploadAutomatically;
	private final boolean replaceArtifacts;

	private final String sourceRegexp;

	private final String releaseName;

	@DataBoundConstructor
	public SFEEReleasePublisher(String sourceRegexp, String releaseName,
			String releaseToReplace, String maturity,
			/* boolean uploadArtifacts, */boolean replaceArtifacts,
			boolean uploadAutomatically) {
		this.releaseToReplace = StringUtils.isBlank(releaseToReplace) ? null
				: releaseToReplace.trim();
		/* this.uploadArtifacts = uploadArtifacts; */
		this.replaceArtifacts = replaceArtifacts;
		this.maturity = maturity;
		this.uploadAutomatically = uploadAutomatically;
		this.sourceRegexp = sourceRegexp;
		this.releaseName = releaseName;
	}

	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.BUILD;
	}

	@Override
	public boolean perform(AbstractBuild<?, ?> build, Launcher launcher,
			BuildListener listener) throws InterruptedException, IOException {

		String version = getVersion(build);
		if (version == null) {
			listener
					.fatalError("SFEE Publisher: Could not find version in build log.");
			return false;
		}

		SourceForgeProject project = build.getProject().getProperty(
				SourceForgeProject.class);
		String releasePackageId = project.getReleasePackageId();

		if (releasePackageId == null) {
			listener.fatalError("SFEE Publisher: No release package set");
			return false;
		}

		SFEEReleaseTask<AbstractBuild> newReleaseTask = new SFEEReleaseTask<AbstractBuild>(
				build, releasePackageId, version, releaseToReplace, maturity,
				uploadArtifacts, replaceArtifacts);
		build.addAction(newReleaseTask);

		if (uploadAutomatically) {
			newReleaseTask.startUpload();
		}

		return true;

	}

	private String getVersion(AbstractBuild<?, ?> build)
			throws FileNotFoundException, IOException {

		DescriptionSetterAction description = build
				.getAction(DescriptionSetterAction.class);
		if (description != null) {
			return description.getDescription();
		}

		Pattern pattern = Pattern.compile(sourceRegexp);
		// Assume default encoding and text files
		String line;
		BufferedReader reader = new BufferedReader(new FileReader(build
				.getLogFile()));
		while ((line = reader.readLine()) != null) {
			Matcher matcher = pattern.matcher(line);
			if (matcher.matches()) {
				String result = releaseName;
				for (int i = 0; i <= matcher.groupCount(); i++) {
					result = result.replace("\\" + i, matcher.group(i));
				}
				return result;
			}
		}
		return null;
	}

	public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

		private DescriptorImpl() {
			super(SFEEReleasePublisher.class);
		}

		@Override
		public String getHelpFile() {
			return null;
		}

		@Override
		public String getDisplayName() {
			return "Publish to SFEE";
		}

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
		}

		@Override
		public Publisher newInstance(StaplerRequest req, JSONObject formData)
				throws FormException {
			return req.bindJSON(SFEEReleasePublisher.class, formData);
		}

		@Extension
		public static final DescriptorImpl INSTANCE = new DescriptorImpl();
	}

	@Override
	public BuildStepDescriptor<Publisher> getDescriptor() {
		return DescriptorImpl.INSTANCE;
	}

	public String getReleaseToReplace() {
		return releaseToReplace;
	}

	public boolean isUploadArtifacts() {
		return uploadArtifacts;
	}

	public boolean isReplaceArtifacts() {
		return replaceArtifacts;
	}

	public String getMaturity() {
		return maturity;
	}

	public boolean isUploadAutomatically() {
		return uploadAutomatically;
	}

	public String getSourceRegexp() {
		return sourceRegexp;
	}

	public String getReleaseName() {
		return releaseName;
	}

}
