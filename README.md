
# DevOps Deploy Plugin for SCC Workload Protection

This plugin enables seamless integration of security best practices into your CI/CD workflows using IBM DevOps Automation. By leveraging SCC Workload Protection, it ensures that security and compliance checks are automatically enforced during application deployment, providing a secure and efficient DevOps process.

## Configuration

Follow these basic steps to configure the WP plugin. You can download it from the plugin folder (`plugin.zip`). This plugin contains three processes:

1.  **Install Security and Compliance Scanner**
2.  **Run Security and Compliance Testing**
3.  **Start Runtime Continuous Security Scanning**

### Install Security and Compliance Scanner

This process installs the CLI tools necessary for extensive Docker image vulnerability and policy scanning. No configuration is needed; it automatically pulls and installs the CLI scanner.

### Run Security and Compliance Testing

This process provides a wide range of security and compliance scanning. To configure it, provide the following information in the plugin edit window:

1.  **URL**: The endpoint with `https`. For example: `https://us-south.security-compliance-xxxxx.cloud.ibm.com`
2.  **Secure API Token**: Obtain this token from the IBM SCC WP credential sections.
3.  **Docker Image Name**: The Docker image name, pulled using the Docker utility command available in DevOps Deploy. Example: `yourname/pizzaapp:${p:version.name}` (Note: Ensure you include the tag with your Docker image).
4.  **Postprocessing Script (Optional)**: If desired, configure the status based on the number of vulnerabilities and policy issues using a Groovy script in post post-processing field.

### Start Runtime Continuous Security Scanning

This process starts runtime scanning and updates continuous results on the SCCWP dashboard. It requires information about the SCCWP server:

1.  **Collector Endpoint**: Provide this information based on your SCC WP cloud environment. Example: `ingest.us-south.xxxx-compliance-xxx.cloud.ibm.com` (Note: Do not use `https` as a prefix).
2.  **Collector API Endpoint**: Obtain this from your SCCWP cloud account. Typically, it's the same as the Collector Endpoint, minus the "ingest." prefix. Example: `us-south.xxxx-compliance-xxx.cloud.ibm.com`
3.  **Collector Port**: Usually `6443`.
4.  **Tag Data**: Provide as per your convenience. Example: `DevOps`.
5.  **Script Directory**: This is crucial. The Continuous Security scanning requires an extensive script (`install-agent.sh`) based on your OS. For macOS and Linux, download it [here](https://github.com/ankit6133/SCCWP_Plugin/tree/main/plugin) and place it in your DevOps Deploy server's `/root` location, else for other OS you can get it from SCCWP team and place it to the "/root" directory. If placed elsewhere, provide the script path in the prompt window.

## Checking Security and Compliance Scanning Results

After the process runs, check the logs for details on the number of critical, high, medium, and low vulnerabilities. It also provides details on policy violations and recommendations.

You can use DeVOps Deploy feature and "Add Version links for components" to access the SCC WP dashboards seamlessly, which offer in-depth information about static and runtime vulnerabilities. (Note: Please login to your IBM account before clicking on the dashboards link. This is intended behaiour)
