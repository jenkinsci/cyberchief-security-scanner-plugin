package io.jenkins.plugins.cyberchief;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.io.IOException;
import javax.servlet.ServletException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public class CyberChiefScanBuilder extends Builder implements SimpleBuildStep {

    private Secret authToken;
    private String apiUrl;
    private String apiName;
    private String raiderName;
    private String[] regions;
    private String[] frameworks;
    private String[] services;
    private String scanType;
    private String testScope;
    private boolean failOnHighVulns;
    private boolean failOnHighMediumVulns;
    private boolean requestComplete;

    @DataBoundConstructor
    public CyberChiefScanBuilder(
            Secret authToken,
            String apiUrl,
            String apiName,
            String raiderName,
            String[] regions,
            String[] frameworks,
            String[] services,
            String scanType,
            String testScope,
            boolean failOnHighVulns,
            boolean failOnHighMediumVulns) {
        this.authToken = authToken;
        this.apiUrl = apiUrl;
        this.scanType = scanType;
        this.apiName = apiName;
        this.raiderName = raiderName;
        this.regions = regions;
        this.frameworks = frameworks;
        this.services = services;
        this.testScope = testScope;
        this.failOnHighVulns = failOnHighVulns;
        this.failOnHighMediumVulns = failOnHighMediumVulns;
        this.requestComplete = false;
    }

    public Secret getAuthToken() {
        return authToken;
    }

    public String getApiUrl() {
        return apiUrl;
    }

    public String getApiName() {
        return apiName;
    }

    public String getRaiderName() {
        return raiderName;
    }

    public String[] getRegions() {
        return regions;
    }

    public String[] getFrameworks() {
        return frameworks;
    }

    public String[] getServices() {
        return services;
    }

    public String getScanType() {
        return scanType;
    }

    public String getTestScope() {
        return testScope;
    }

    public boolean getFailOnHighVulns() {
        return failOnHighVulns;
    }

    public boolean getFailOnHighMediumVulns() {
        return failOnHighMediumVulns;
    }

    @DataBoundSetter
    public void setAuthToken(Secret authToken) {
        this.authToken = authToken;
    }

    @DataBoundSetter
    public void setScanType(String scanType) {
        this.scanType = scanType;
    }

    @DataBoundSetter
    public void setApiName(String apiName) {
        this.apiName = apiName;
    }

    @DataBoundSetter
    public void setRaiderName(String raiderName) {
        this.raiderName = raiderName;
    }

    @DataBoundSetter
    public void setRegions(String[] regions) {
        this.regions = regions;
    }

    @DataBoundSetter
    public void setFrameworks(String[] frameworks) {
        this.frameworks = frameworks;
    }

    @DataBoundSetter
    public void setServices(String[] services) {
        this.services = services;
    }

    @DataBoundSetter
    public void setTestScope(String testScope) {
        this.testScope = testScope;
    }

    @DataBoundSetter
    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    @DataBoundSetter
    public void setFailOnHighVulns(boolean failOnHighVulns) {
        this.failOnHighVulns = failOnHighVulns;
    }

    @DataBoundSetter
    public void setFailOnHighMediumVulns(boolean failOnHighMediumVulns) {
        this.failOnHighMediumVulns = failOnHighMediumVulns;
    }

    public void waitForApiRequestCompletion(
            CyberChiefScanAction cyberChiefScanAction,
            Secret authToken,
            boolean requestComplete,
            boolean failOnHighVulns,
            boolean failOnHighMediumVulns,
            TaskListener listener)
            throws InterruptedException {

        String statusUrl = cyberChiefScanAction.extractStatusUrl();
        if (statusUrl != null) {
            cyberChiefScanAction.pollStatusUrl(
                    statusUrl, authToken, requestComplete, failOnHighVulns, failOnHighMediumVulns, listener);
        }
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws InterruptedException, IOException {

        listener.getLogger().println("API URL: " + apiUrl);
        listener.getLogger().println("Scan Type: " + scanType);
        listener.getLogger().println("Test Scope: " + testScope);
        listener.getLogger().println("API Name: " + apiName);
        listener.getLogger().println("Raider Name: " + raiderName);

        listener.getLogger().println("Fail on High Vulns: " + failOnHighVulns);
        listener.getLogger().println("Fail on High and Medium: " + failOnHighMediumVulns);

        CyberChiefScanAction cyberChiefScanAction = new CyberChiefScanAction(authToken, testScope);

        if ("raider".equals(scanType)) {
            cyberChiefScanAction.makeRaiderScanRequest(
                    apiUrl, authToken, raiderName, regions, frameworks, services, listener);
        } else if ("api".equals(scanType)) {
            cyberChiefScanAction.makeApiScanRequest(apiUrl, authToken, apiName, listener);
        } else {
            cyberChiefScanAction.makeWebAppScanRequest(apiUrl, authToken, testScope, listener);
        }

        if (failOnHighVulns || failOnHighMediumVulns) {
            waitForApiRequestCompletion(
                    cyberChiefScanAction, authToken, requestComplete, failOnHighVulns, failOnHighMediumVulns, listener);
        }

        run.addAction(cyberChiefScanAction);
    }

    @Symbol("greet")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        public FormValidation doCheckAuthToken(@QueryParameter String value) throws IOException, ServletException {
            if (value.length() == 0) return FormValidation.error("Authentication Token is required");
            return FormValidation.ok();
        }

        public ListBoxModel doFillScanTypeItems() {
            ListBoxModel items = new ListBoxModel();

            // Add your allowed options here
            items.add("Web App Scan", "web_app");
            items.add("Bolt API Security", "api");
            items.add("Raider CPSM", "raider");

            return items;
        }

        public ListBoxModel doFillTestScopeItems() {
            ListBoxModel items = new ListBoxModel();

            // Add your allowed options here
            items.add("Reconnaissance", "reconnaissance");
            items.add("Attack", "attack");
            items.add("Infiltration", "infiltration");

            return items;
        }

        public ListBoxModel doFillRegionsItems() {
            ListBoxModel items = new ListBoxModel();

            items.add("All", "");
            items.add("us-east-1", "us-east-1");
            items.add("us-east-2", "us-east-2");
            items.add("us-west-1", "us-west-1");
            items.add("us-west-2", "us-west-2");
            items.add("af-south-1", "af-south-1");
            items.add("ap-east-1", "ap-east-1");
            items.add("ap-southeast-1", "ap-southeast-1");
            items.add("ap-southeast-2", "ap-southeast-2");
            items.add("ap-southeast-3", "ap-southeast-3");
            items.add("ap-south-1", "ap-south-1");
            items.add("ap-northeast-1", "ap-northeast-1");
            items.add("ap-northeast-2", "ap-northeast-2");
            items.add("ap-northeast-3", "ap-northeast-3");
            items.add("ca-central-1", "ca-central-1");
            items.add("eu-central-1", "eu-central-1");
            items.add("eu-central-2", "eu-central-2");
            items.add("eu-west-1", "eu-west-1");
            items.add("eu-west-2", "eu-west-2");
            items.add("eu-west-3", "eu-west-3");
            items.add("eu-south-1", "eu-south-1");
            items.add("eu-south-2", "eu-south-2");
            items.add("eu-north-1", "eu-north-1");
            items.add("me-south-1", "me-south-1");
            items.add("me-central-1", "me-central-1");
            items.add("sa-east-1", "sa-east-1");

            return items;
        }

        public ListBoxModel doFillFrameworksItems() {
            ListBoxModel items = new ListBoxModel();

            items.add("All", "");
            items.add("AWS Audit Manager Control Tower Guardrails", "aws_audit_manager_control_tower_guardrails_aws");
            items.add("AWS Foundational Security Best Practices", "aws_foundational_security_best_practices_aws");
            items.add(
                    "AWS Well Architected Framework Reliability Pillar",
                    "aws_well_architected_framework_reliability_pillar_aws");
            items.add(
                    "AWS Well Architected Framework Security Pillar",
                    "aws_well_architected_framework_security_pillar_aws");
            items.add("CISA", "cisa_aws");
            items.add("CIS 1.4", "cis_1.4_aws");
            items.add("CIS 1.5", "cis_1.5_aws");
            items.add("CIS 2.0", "cis_2.0_aws");
            items.add("ENS RD 2022", "ens_rd2022_aws");
            items.add("Fedramp low rev4", "fedramp_low_revision_4_aws");
            items.add("FedRAMP Moderate rev4", "fedramp_moderate_revision_4_aws");
            items.add("FFIEC", "ffiec_aws");
            items.add("GDPR", "gdpr_aws");
            items.add("GxP EU Annex 11", "gxp_eu_annex_11_aws");
            items.add("GxP 21 CFR part 111", "gxp_21_cfr_part_11_aws");
            items.add("HIPAA", "hipaa_aws");
            items.add("ISO 27001-2013", "iso27001_2013_aws");
            items.add("Mitre Attack", "mitre_attack_aws");
            items.add("NIST 800-53 rev4", "nist_800_53_revision_4_aws");
            items.add("NIST 800-53 rev5", "nist_800_53_revision_5_aws");
            items.add("NIST 800-171 rev2", "nist_800_171_revision_2_aws");
            items.add("NIST CSF 1.1", "nist_csf_1.1_aws");
            items.add("PCI 3.2.1", "pci_3.2.1_aws");
            items.add("RBI security framework", "rbi_cyber_security_framework_aws");
            items.add("SOC2", "soc2_aws");

            return items;
        }

        public ListBoxModel doFillServicesItems() {
            ListBoxModel items = new ListBoxModel();

            items.add("All", "");
            items.add("Accessanalyzer", "accessanalyzer");
            items.add("Account", "account");
            items.add("Acm", "acm");
            items.add("Apigateway", "apigateway");
            items.add("Apigatewayv2", "apigatewayv2");
            items.add("Appstream", "appstream");
            items.add("Autoscaling", "autoscaling");
            items.add("Awslambda", "awslambda");
            items.add("Backup", "backup");
            items.add("Cloudformation", "cloudformation");
            items.add("Cloudfront", "cloudfront");
            items.add("Cloudtrail", "cloudtrail");
            items.add("Cloudwatch", "cloudwatch");
            items.add("Codeartifact", "codeartifact");
            items.add("Codebuild", "codebuild");
            items.add("Config", "config");
            items.add("Directoryservice", "directoryservice");
            items.add("Drs", "drs");
            items.add("Dynamodb", "dynamodb");
            items.add("Ec2", "ec2");
            items.add("Ecr", "ecr");
            items.add("Ecs", "ecs");
            items.add("Efs", "efs");
            items.add("Eks", "eks");
            items.add("Elb", "elb");
            items.add("Elbv2", "elbv2");
            items.add("Emr", "emr");
            items.add("Fms", "fms");
            items.add("Glacier", "glacier");
            items.add("Glue", "glue");
            items.add("Guardduty", "guardduty");
            items.add("Iam", "iam");
            items.add("Inspector2", "inspector2");
            items.add("Kms", "kms");
            items.add("Macie", "macie");
            items.add("Networkfirewall", "networkfirewall");
            items.add("Opensearch", "opensearch");
            items.add("Organizations", "organizations");
            items.add("Rds", "rds");
            items.add("Redshift", "redshift");
            items.add("Resourceexplorer2", "resourceexplorer2");
            items.add("Route53", "route53");
            items.add("S3", "s3");
            items.add("Sagemaker", "sagemaker");
            items.add("Secretsmanager", "secretsmanager");
            items.add("Securityhub", "securityhub");
            items.add("Shield", "shield");
            items.add("Sns", "sns");
            items.add("Sqs", "sqs");
            items.add("Ssm", "ssm");
            items.add("Ssmincidents", "ssmincidents");
            items.add("Trustedadvisor", "Trustedadvisor");
            items.add("Vpc", "vpc");
            items.add("Workspaces", "workspaces");

            return items;
        }

        public FormValidation doCheckRaiderName(@QueryParameter String value) throws IOException, ServletException {
            if (value.length() == 0) return FormValidation.error("Raider name is required");
            return FormValidation.ok();
        }

        public FormValidation doCheckApiName(@QueryParameter String value) throws IOException, ServletException {
            if (value.length() == 0) return FormValidation.error("API name is required");
            return FormValidation.ok();
        }

        public FormValidation doCheckApiUrl(@QueryParameter String value) throws IOException, ServletException {
            if (value.length() == 0) return FormValidation.error("API URL is required");
            return FormValidation.ok();
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Cyber Chief Security Scanner";
        }
    }
}
