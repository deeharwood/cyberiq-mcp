# atlas_knowledge.py - MITRE ATLAS / SAFE-AI Knowledge Base for CyberIQ
# Source: MITRE SAFE-AI Framework (MP250397, April 2025) + MITRE ATLAS v5.1.0
# This module provides structured ATLAS technique data with SAFE-AI control mappings

ATLAS_TACTICS = {
    "AML.TA0002": {"name": "Reconnaissance", "description": "The adversary is trying to gather information about AI systems to plan attacks. This includes scanning for ML artifacts, searching application repositories, and researching publicly available adversarial vulnerability analysis."},
    "AML.TA0003": {"name": "Resource Development", "description": "The adversary is trying to establish resources to support operations against AI systems. This includes acquiring infrastructure, public ML artifacts, and developing capabilities."},
    "AML.TA0004": {"name": "Initial Access", "description": "The adversary is trying to get into the AI system. This includes exploiting public-facing applications, ML supply chain compromise, phishing, and LLM prompt injection."},
    "AML.TA0000": {"name": "ML Model Access", "description": "The adversary is trying to gain access to ML models. This includes inference API access, full model access, physical environment access, and access through ML-enabled products or services."},
    "AML.TA0005": {"name": "Execution", "description": "The adversary is trying to run malicious code or commands within AI systems. This includes command and scripting interpreter abuse, LLM plugin compromise, LLM jailbreak, and user execution."},
    "AML.TA0006": {"name": "Persistence", "description": "The adversary is trying to maintain their foothold in AI systems. This includes backdooring ML models, LLM prompt injection for persistence, poisoning training data, and LLM prompt self-replication."},
    "AML.TA0012": {"name": "Privilege Escalation", "description": "The adversary is trying to gain higher-level permissions in AI systems. This includes LLM jailbreak to bypass safety guardrails, LLM plugin compromise, and LLM prompt injection to escalate capabilities."},
    "AML.TA0007": {"name": "Defense Evasion", "description": "The adversary is trying to avoid detection by AI security systems. This includes evading ML models, LLM jailbreak to bypass content filters, and LLM prompt injection to circumvent safety systems."},
    "AML.TA0013": {"name": "Credential Access", "description": "The adversary is trying to steal credentials for AI systems. This includes exploiting unsecured credentials such as API keys and model access tokens."},
    "AML.TA0008": {"name": "Discovery", "description": "The adversary is trying to understand the AI system and its environment. This includes discovering AI model outputs, LLM hallucinations, ML artifacts, model family, and model ontology."},
    "AML.TA0009": {"name": "Collection", "description": "The adversary is trying to gather data from AI systems. This includes collecting data from information repositories, local systems, and ML artifact collection."},
    "AML.TA0001": {"name": "ML Attack Staging", "description": "The adversary is preparing ML-specific attacks. This includes crafting adversarial data, creating proxy ML models, verifying attacks, evading ML models, and poisoning training data."},
    "AML.TA0010": {"name": "Exfiltration", "description": "The adversary is trying to steal data from AI systems. This includes exfiltration via cyber means, ML inference API, LLM data leakage, and LLM meta prompt extraction."},
    "AML.TA0011": {"name": "Impact", "description": "The adversary is trying to disrupt, damage, or manipulate AI systems. This includes cost harvesting, denial of ML service, eroding dataset/model integrity, external harms, publishing hallucinated entities, spamming with chaff data, and publishing poisoned datasets/models."}
}

ATLAS_TECHNIQUES = {
    "AML.T0006": {"name": "Active Scanning", "tactic": "Reconnaissance", "tactic_id": "AML.TA0002", "attck_shared": True, "description": "Adversaries scan for AI system components, ML model endpoints, and API configurations to identify attack surfaces.", "mitigations": ["Network monitoring", "Rate limiting", "API endpoint hardening"]},
    "AML.T0004": {"name": "Search Application Repositories", "tactic": "Reconnaissance", "tactic_id": "AML.TA0002", "attck_shared": False, "description": "Adversaries search application repositories for ML model artifacts, training data references, and API documentation."},
    "AML.T0001": {"name": "Search for Publicly Available Adversarial Vulnerability Analysis", "tactic": "Reconnaissance", "tactic_id": "AML.TA0002", "attck_shared": False, "description": "Adversaries research published adversarial ML attacks, exploit code, and vulnerability analyses targeting AI systems."},
    "AML.T0000": {"name": "Search for Victim's Publicly Available Research Materials", "tactic": "Reconnaissance", "tactic_id": "AML.TA0002", "attck_shared": False, "description": "Adversaries search for victim's published research papers, model cards, and technical documentation about their AI systems."},
    "AML.T0003": {"name": "Search Victim-Owned Websites", "tactic": "Reconnaissance", "tactic_id": "AML.TA0002", "attck_shared": False, "description": "Adversaries scan victim-owned websites for information about AI implementations, APIs, and model details."},
    "AML.T0008": {"name": "Acquire Infrastructure", "tactic": "Resource Development", "tactic_id": "AML.TA0003", "attck_shared": False, "description": "Adversaries acquire computing infrastructure to support attacks against AI systems."},
    "AML.T0002": {"name": "Acquire Public ML Artifacts", "tactic": "Resource Development", "tactic_id": "AML.TA0003", "attck_shared": False, "description": "Adversaries acquire publicly available ML models, datasets, or tools to use in attacks."},
    "AML.T0017": {"name": "Develop Capabilities", "tactic": "Resource Development", "tactic_id": "AML.TA0003", "attck_shared": True, "description": "Adversaries develop custom tools, adversarial examples, or attack frameworks targeting AI systems."},
    "AML.T0021": {"name": "Establish Accounts", "tactic": "Resource Development", "tactic_id": "AML.TA0003", "attck_shared": True, "description": "Adversaries create accounts on AI platforms to gain access for reconnaissance or attack staging."},
    "AML.T0016": {"name": "Obtain Capabilities", "tactic": "Resource Development", "tactic_id": "AML.TA0003", "attck_shared": True, "description": "Adversaries obtain adversarial ML tools, pre-built attack frameworks, or exploit code."},
    "AML.T0015": {"name": "Evade ML Model", "tactic": "Initial Access", "tactic_id": "AML.TA0004", "attck_shared": False, "description": "Adversaries craft inputs designed to evade ML model detection. Also appears in Defense Evasion and ML Attack Staging.", "also_in_tactics": ["AML.TA0007", "AML.TA0001"]},
    "AML.T0049": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "tactic_id": "AML.TA0004", "attck_shared": True, "description": "Adversaries exploit vulnerabilities in public-facing AI applications, APIs, or inference endpoints."},
    "AML.T0051": {"name": "LLM Prompt Injection", "tactic": "Initial Access", "tactic_id": "AML.TA0004", "attck_shared": False, "description": "Adversaries inject malicious instructions into LLM prompts to manipulate model behavior. This is the #1 threat to LLM systems. Appears across 4 tactic categories: Initial Access, Persistence, Privilege Escalation, and Defense Evasion. Includes both direct injection (user crafts malicious prompt) and indirect injection (malicious content ingested from external data sources).", "also_in_tactics": ["AML.TA0006", "AML.TA0012", "AML.TA0007"], "safe_ai_controls": {"AI Platform": ["AC-06-00", "AU-06-00", "CM-05-00", "SI-03-00", "SI-04-00", "SI-10-00"], "AI Models": ["AC-03-00", "SI-03-00", "SI-04-00", "SI-10-00"]}},
    "AML.T0010": {"name": "ML Supply Chain Compromise", "tactic": "Initial Access", "tactic_id": "AML.TA0004", "attck_shared": False, "description": "Adversaries compromise the ML supply chain to inject malicious code, backdoored models, or poisoned data. Sub-techniques: .001 ML Software, .002 Data, .003 Model.", "subtechniques": ["AML.T0010.001 ML Software", "AML.T0010.002 Data", "AML.T0010.003 Model"]},
    "AML.T0052": {"name": "Phishing", "tactic": "Initial Access", "tactic_id": "AML.TA0004", "attck_shared": True, "description": "Adversaries use phishing to gain access to AI systems, training pipelines, or model repositories."},
    "AML.T0040": {"name": "AI Model Inference API Access", "tactic": "ML Model Access", "tactic_id": "AML.TA0000", "attck_shared": False, "description": "Adversaries access AI model inference APIs to query models, probe for vulnerabilities, or extract information about model behavior."},
    "AML.T0044": {"name": "Full ML Model Access", "tactic": "ML Model Access", "tactic_id": "AML.TA0000", "attck_shared": False, "description": "Adversaries gain full access to ML model weights, parameters, and architecture."},
    "AML.T0047": {"name": "ML-Enabled Product or Service", "tactic": "ML Model Access", "tactic_id": "AML.TA0000", "attck_shared": False, "description": "Adversaries access AI systems through ML-enabled products or services that expose model functionality."},
    "AML.T0041": {"name": "Physical Environment Access", "tactic": "ML Model Access", "tactic_id": "AML.TA0000", "attck_shared": False, "description": "Adversaries physically access the environment where AI systems operate to manipulate sensors, data collection, or infrastructure."},
    "AML.T0050": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "tactic_id": "AML.TA0005", "attck_shared": True, "description": "Adversaries abuse command and scripting interpreters within AI systems to execute malicious code."},
    "AML.T0053": {"name": "LLM Plugin Compromise", "tactic": "Execution", "tactic_id": "AML.TA0005", "attck_shared": False, "description": "Adversaries compromise LLM plugins, extensions, or tool integrations (including MCP servers) to execute unauthorized actions, exfiltrate data, or escalate privileges. Also appears in Privilege Escalation.", "also_in_tactics": ["AML.TA0012"], "safe_ai_controls": {"AI Platform": ["AC-06-00", "AC-24-00", "CM-05-00", "CM-07-00", "CM-13-00", "SA-08-00", "SC-39-00", "SI-03-00", "SI-10-00"]}},
    "AML.T0054": {"name": "LLM Jailbreak", "tactic": "Execution", "tactic_id": "AML.TA0005", "attck_shared": False, "description": "Adversaries use jailbreak techniques to bypass LLM safety guardrails and generate harmful, restricted, or policy-violating content. Also appears in Defense Evasion.", "also_in_tactics": ["AML.TA0007"]},
    "AML.T0011": {"name": "User Execution", "tactic": "Execution", "tactic_id": "AML.TA0005", "attck_shared": True, "description": "Adversaries trick users into executing malicious actions within AI systems."},
    "AML.T0018": {"name": "Backdoor ML Model", "tactic": "Persistence", "tactic_id": "AML.TA0006", "attck_shared": False, "description": "Adversaries embed hidden behaviors (backdoors) in ML models that are triggered by specific inputs during operations. Also appears in ML Attack Staging.", "also_in_tactics": ["AML.TA0001"]},
    "AML.T0020": {"name": "Poison Training Data", "tactic": "Persistence", "tactic_id": "AML.TA0006", "attck_shared": False, "description": "Adversaries corrupt training data to create backdoors, bias outputs, or degrade model performance. Also appears in ML Attack Staging.", "also_in_tactics": ["AML.TA0001"], "safe_ai_controls": {"Environment": ["SC-07-00", "SC-08-00"], "AI Platform": ["SC-08-00"], "AI Data": ["AC-14-00", "CM-07-00", "SC-08-00", "SI-04-00", "SI-10-00"]}},
    "AML.T0061": {"name": "LLM Prompt Self-Replication", "tactic": "Persistence", "tactic_id": "AML.TA0006", "attck_shared": False, "description": "Adversary prompts propagate autonomously through AI systems, creating persistent malicious behaviors across sessions or users."},
    "AML.T0055": {"name": "Unsecured Credentials", "tactic": "Credential Access", "tactic_id": "AML.TA0013", "attck_shared": True, "description": "Adversaries exploit unsecured API keys, model access tokens, or credentials left exposed in code, configuration files, or environment variables."},
    "AML.T0063": {"name": "Discover AI Model Outputs", "tactic": "Discovery", "tactic_id": "AML.TA0008", "attck_shared": False, "description": "Adversaries probe AI models to understand their output patterns, decision boundaries, and behavior."},
    "AML.T0062": {"name": "Discover LLM Hallucinations", "tactic": "Discovery", "tactic_id": "AML.TA0008", "attck_shared": False, "description": "Adversaries map where an LLM hallucinates to exploit those gaps. Hallucinated package names, URLs, or entities can be registered by attackers to create supply chain attacks."},
    "AML.T0007": {"name": "Discover ML Artifacts", "tactic": "Discovery", "tactic_id": "AML.TA0008", "attck_shared": False, "description": "Adversaries discover ML model files, weights, configurations, and other artifacts stored in the environment."},
    "AML.T0014": {"name": "Discover ML Model Family", "tactic": "Discovery", "tactic_id": "AML.TA0008", "attck_shared": False, "description": "Adversaries determine the type/family of ML model being used to select appropriate attack techniques."},
    "AML.T0013": {"name": "Discover ML Model Ontology", "tactic": "Discovery", "tactic_id": "AML.TA0008", "attck_shared": False, "description": "Adversaries discover the structure, classes, and relationships within an ML model's ontology."},
    "AML.T0036": {"name": "Data from Information Repositories", "tactic": "Collection", "tactic_id": "AML.TA0009", "attck_shared": True, "description": "Adversaries collect data from information repositories connected to AI systems."},
    "AML.T0037": {"name": "Data from Local System", "tactic": "Collection", "tactic_id": "AML.TA0009", "attck_shared": True, "description": "Adversaries collect data from local systems where AI models or training data are stored."},
    "AML.T0035": {"name": "ML Artifact Collection", "tactic": "Collection", "tactic_id": "AML.TA0009", "attck_shared": False, "description": "Adversaries collect ML artifacts including model weights, training data, hyperparameters, and configuration files."},
    "AML.T0043": {"name": "Craft Adversarial Data", "tactic": "ML Attack Staging", "tactic_id": "AML.TA0001", "attck_shared": False, "description": "Adversaries create specially crafted inputs designed to cause misclassification, unsafe outputs, or model failures."},
    "AML.T0005": {"name": "Create Proxy ML Model", "tactic": "ML Attack Staging", "tactic_id": "AML.TA0001", "attck_shared": False, "description": "Adversaries create a substitute model that mimics the target model to develop and test attacks offline."},
    "AML.T0042": {"name": "Verify Attack", "tactic": "ML Attack Staging", "tactic_id": "AML.TA0001", "attck_shared": False, "description": "Adversaries verify that their crafted attack will be effective against the target AI system."},
    "AML.T0025": {"name": "Exfiltration via Cyber Means", "tactic": "Exfiltration", "tactic_id": "AML.TA0010", "attck_shared": False, "description": "Adversaries exfiltrate ML models, training data, or sensitive information via traditional cyber exfiltration channels."},
    "AML.T0024": {"name": "Exfiltration via ML Inference API", "tactic": "Exfiltration", "tactic_id": "AML.TA0010", "attck_shared": False, "description": "Adversaries extract model information through carefully crafted queries to the inference API."},
    "AML.T0057": {"name": "LLM Data Leakage", "tactic": "Exfiltration", "tactic_id": "AML.TA0010", "attck_shared": False, "description": "Adversaries extract sensitive training data, proprietary information, or PII from LLMs through targeted queries or prompt engineering."},
    "AML.T0056": {"name": "LLM Meta Prompt Extraction", "tactic": "Exfiltration", "tactic_id": "AML.TA0010", "attck_shared": False, "description": "Adversaries extract system prompts, safety instructions, or configuration from LLMs to understand and bypass safety controls. Also appears in Collection.", "also_in_tactics": ["AML.TA0009"]},
    "AML.T0034": {"name": "Cost Harvesting", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries deliberately increase computational costs by flooding AI systems with expensive queries or crafting inputs that consume excessive resources.", "safe_ai_controls": {"Environment": ["AU-06-05", "SC-05-00", "SC-06-00"], "AI Platform": ["AU-06-05", "SC-05-00", "SC-06-00"]}},
    "AML.T0029": {"name": "Denial of ML Service", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries disrupt AI services by overloading inference endpoints or causing model failures."},
    "AML.T0059": {"name": "Erode Dataset Integrity", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries gradually corrupt training or operational data over time, degrading model performance subtly."},
    "AML.T0031": {"name": "Erode ML Model Integrity", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries degrade model integrity through manipulation of model parameters, weights, or decision boundaries."},
    "AML.T0048": {"name": "External Harms", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "AI systems cause real-world harms including privacy breaches, discrimination, physical safety risks, or reputational damage."},
    "AML.T0060": {"name": "Publish Hallucinated Entities", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries create real-world entities (packages, domains, accounts) matching what an LLM hallucinates, creating supply chain or trust attacks."},
    "AML.T0046": {"name": "Spamming ML System with Chaff Data", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries flood AI systems with irrelevant data to overwhelm processing, increase false positives, and degrade analyst efficiency."},
    "AML.T0019": {"name": "Publish Poisoned Datasets", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries publish poisoned datasets to public repositories to compromise organizations that use them for training."},
    "AML.T0058": {"name": "Publish Poisoned Models", "tactic": "Impact", "tactic_id": "AML.TA0011", "attck_shared": False, "description": "Adversaries publish backdoored or poisoned models to public repositories to compromise organizations that deploy them."},
    "AML.T0012": {"name": "Valid Accounts", "tactic": "Defense Evasion", "tactic_id": "AML.TA0007", "attck_shared": True, "description": "Adversaries use compromised valid credentials to access AI systems while blending in with legitimate activity."}
}

# SAFE-AI Threat-to-Control Mappings (from Appendix C)
SAFE_AI_THREATS = {
    "Loss of Models": {"atlas_id": "AML.T0031", "description": "Malicious destruction or corruption of AI models. Key consideration is access control and write access.", "controls": {"Environment": ["AC-03-00","AC-06-00","CM-07-00","SC-37-00"], "AI Platform": ["AC-03-00","AC-05-00","AC-06-00","AU-02-00","CM-05-00"], "AI Models": ["AC-03-00","AC-05-00","AC-06-00","AU-02-00","AU-03-00","CM-05-00","CM-07-00","SC-24-00","SI-20-00"], "AI Data": ["AC-06-00"]}, "residual_risk": "Insider threats not addressed by access control. Model corruption could occur undetected."},
    "Model Poisoning": {"atlas_id": "AML.T0020", "description": "Attacks that modify code, objective functions, model parameters, or training data to undermine reliability, integrity and availability.", "controls": {"AI Platform": ["SR-03-00"]}, "residual_risk": "Insider threats remain. Attack surface is very large and not completely known."},
    "Insecure APIs": {"atlas_id": "AML.T0040", "description": "Insecure APIs allow unauthorized access, malicious inputs, or AI system disruption. Inference APIs are particularly vulnerable.", "controls": {"Environment": ["RA-05-00","SC-05-00","SC-23-00","SR-09-00"], "AI Platform": ["AC-24-00","SR-03-00","SR-11-00"], "AI Models": ["SR-03-00"]}, "residual_risk": "Authorized users may abuse access. Open-source recon gives adversaries opportunity to find zero-day exploits."},
    "Data Poisoning": {"atlas_id": "AML.T0020", "description": "Poisoned data compromises AI decision-making and biases outputs. Can embed backdoor triggers activated by designated input.", "controls": {"Environment": ["SC-07-00","SC-08-00"], "AI Platform": ["SC-08-00"], "AI Data": ["AC-14-00","CM-07-00","SC-08-00","SI-04-00","SI-10-00"]}, "residual_risk": "Ground truth baseline for validation could be incomplete or unrepresentative."},
    "Model Exposure": {"atlas_id": "AML.T0024", "description": "Attackers extract trained models or collect enough info to create functional copies. Models should be treated as sensitive assets.", "controls": {"Environment": ["AC-03-00","AC-06-00","AC-20-00","AC-24-00","CM-07-00","SC-04-00","SC-08-00","SC-28-00","SC-39-00"], "AI Platform": ["AC-03-00","AC-06-00","AC-20-00","AC-24-00","AU-02-00","CM-05-00","SC-04-00","SC-08-00","SC-39-00"], "AI Models": ["AC-03-00","AC-05-00","AC-06-00","AC-20-00","AU-02-00","AU-03-00","CM-05-00","CM-07-00","SC-04-00","SC-12-00","SC-28-00","SI-20-00"], "AI Data": ["AC-03-00","AC-06-00","AC-20-00","SC-04-00","SC-08-00","SC-28-00"]}, "residual_risk": "Model knowledge could be disclosed through public documents or inadvertent authorized channels."},
    "Sensitive Data Exposure": {"atlas_id": "AML.T0048", "description": "Unauthorized access to sensitive data during development, testing, and deployment of AI systems.", "controls": {"Environment": ["PM-12-00","SC-04-00","SC-08-00","SC-28-00"], "AI Platform": ["PM-12-00","SA-17-00","SC-04-00","SC-08-00","SC-28-00"], "AI Models": ["SC-04-00","SC-08-00","SC-28-00"], "AI Data": ["SC-04-00","SC-08-00","SC-13-00","SC-28-00"]}, "residual_risk": "Insider threats and third-party components may expose sensitive data."},
    "Sensitive Information Disclosure": {"atlas_id": "AML.T0048", "description": "AI inadvertently discloses sensitive info through responses, memorization during training, or crafted prompts inducing leaks.", "controls": {"Environment": ["AC-04-00","AC-04-25","AC-06-00","AC-21-00","AC-24-00","PL-08-00","PM-07-00","PM-18-00"], "AI Platform": ["AC-04-00","AC-04-25","AC-06-00","AC-21-00","AC-23-00","AC-24-00","AU-06-00","SC-28-00","SI-07-00"], "AI Models": ["AC-04-00","AC-04-25","AC-06-00","SC-04-00","SC-08-00","SC-28-00","SI-07-00","SI-20-00"], "AI Data": ["AC-04-00","AC-04-25","AC-06-00","AC-21-00","SC-04-00","SC-08-00","SC-28-00","SI-07-00","SI-20-00"]}, "residual_risk": "Complex AI systems make it difficult to identify all disclosure pathways."},
    "Supply Chain - Models": {"atlas_id": "AML.T0010.003", "description": "Pre-trained models from external sources may contain malicious code or backdoors. Change management critically important.", "controls": {"Environment": ["SR-01-00","SR-03-00","SR-04-00","SR-05-00","SR-06-00","SR-08-00","SR-11-00"], "AI Platform": ["SR-01-00","SR-02-00","SR-03-00","SR-04-00","SR-05-00","SR-06-00","SR-08-00","PM-30-00"], "AI Models": ["SR-01-00","SR-02-00","SR-03-00","SR-06-00","SR-08-00"]}, "residual_risk": "Trusted external sources may be unknowingly compromised."},
    "Supply Chain - Data": {"atlas_id": "AML.T0010.002", "description": "External data sources may be compromised. Provenance documentation is critical.", "controls": {"Environment": ["SR-01-00","SR-04-00","SR-09-00"], "AI Platform": ["AT-03-00","SR-01-00","SR-04-00","SR-05-00"], "AI Data": ["AT-03-00","SR-01-00","SR-04-00","SR-05-00"]}, "residual_risk": "Data supply chain may be too large for controls to detect all threats."},
    "Supply Chain - Tools/Platforms": {"atlas_id": "AML.T0010.001", "description": "AI tools and platforms from external sources may have vulnerabilities. SBOMs and AIBOMs are critical.", "controls": {"Environment": ["SR-03-00"], "AI Platform": ["SR-03-00","SR-04-00","SR-05-00","SR-11-00"]}, "residual_risk": "Supply chain is so large that SBOMs may not sufficiently mitigate all threats."},
    "Direct Prompt Injection": {"atlas_id": "AML.T0051", "description": "Adversaries craft malicious prompts to manipulate AI to generate harmful content, bypass controls, or execute privileged commands.", "controls": {"Environment": ["AC-03-00"], "AI Platform": ["AC-03-00","SI-03-00","SI-04-00","SI-10-00"]}, "residual_risk": "Prompts may be injected from any uncontrolled source. AI logic lacks transparency of traditional software."},
    "Indirect Prompt Injection": {"atlas_id": "AML.T0051", "description": "Malicious prompts ingested from separate data sources during normal operation. Users may never be aware of the injection.", "controls": {"AI Platform": ["AC-06-00","AU-06-00","CM-05-00","SI-03-00","SI-04-00","SI-10-00"]}, "residual_risk": "Prompts may be injected from any uncontrolled data source. Unknown logic flaws may be exploited."},
    "Insider Threats": {"atlas_id": "AML.T0012", "description": "Insiders exploit access privileges for data theft or sabotage. AI development practices often lack traditional process controls.", "controls": {"Environment": ["AC-05-00","AC-06-00","AC-24-00","CM-11-00","IA-02-00","IA-08-00","MA-05-00","PM-12-00","SC-28-00","SI-03-00","SI-04-00","SR-09-00"], "AI Platform": ["AC-05-00","AC-06-00","AC-24-00","CM-11-00","IA-02-00","IA-08-00","MA-05-00","PM-12-00","SC-28-00","SI-03-00","SI-04-00","SR-09-00"], "AI Models": ["PM-12-00","SC-28-00","SI-04-00","SI-20-00"], "AI Data": ["PM-12-00","SC-28-00","SI-04-00","SI-20-00"]}, "residual_risk": "Controls make unauthorized activities harder but cannot completely eliminate risk."},
    "Excessive Agency": {"atlas_id": "AML.T0050", "description": "AI components with capabilities beyond what is necessary. Excessive permissions and unchecked autonomy cause unintended behaviors.", "controls": {"Environment": ["AC-06-00","CM-07-00"], "AI Platform": ["AC-05-00","AC-06-00","CM-07-00"], "AI Models": ["CM-07-00"]}, "residual_risk": "Unfettered access to authorized capabilities may lead to unintended consequences."},
    "Insecure Plugin Design": {"atlas_id": "AML.T0053", "description": "Plugins with insufficient access controls or input validation allow data exfiltration, remote code execution, and privilege escalation.", "controls": {"Environment": ["AC-06-00","CM-07-00","SC-08-00"], "AI Platform": ["AC-06-00","AC-24-00","CM-05-00","CM-07-00","CM-13-00","SA-08-00","SC-39-00","SI-03-00","SI-10-00"]}, "residual_risk": "Plugins introduce plugin-specific risks that may be difficult to fully identify."},
    "AI Bias": {"atlas_id": "AML.T0020", "description": "Biases in data and models lead to inaccurate outcomes or discriminatory treatment. Scale and complexity make bias management challenging.", "controls": {"Environment": ["CA-02-00","CM-02-00","PL-02-00","PL-04-00","SA-10-00"], "AI Platform": ["CA-02-00","CM-02-00","PL-02-00","PL-04-00","SA-10-00"], "AI Data": ["CA-02-00","CM-02-00","PL-02-00","PL-04-00","SA-10-00","SR-04-00"]}, "residual_risk": "Some input sources may not be sufficiently controlled. Data drift can cause biased outcomes."},
    "Identity Spoofing": {"atlas_id": "AML.T0052", "description": "Deep fakes, synthetic identities, and AI-generated content threaten authentication systems including voice spoofing and biometrics.", "controls": {"Environment": ["AC-07-00","AC-14-00","IA-02-00","IA-02-01","IA-02-02","IA-08-00","IA-12-00"], "AI Platform": ["AC-07-00","AC-14-00","IA-02-00","IA-02-01","IA-02-02","IA-08-00","IA-12-00"]}, "residual_risk": "Fake-detectors lag fake-generators, creating vulnerability windows."},
    "Cost Harvesting": {"atlas_id": "AML.T0034", "description": "Adversaries maliciously increase costs by flooding with useless queries or crafting computationally expensive inputs.", "controls": {"Environment": ["AU-06-05","SC-05-00","SC-06-00"], "AI Platform": ["AU-06-05","SC-05-00","SC-06-00"]}, "residual_risk": "Some cost burden or service quality degradation cannot be compensated for."},
    "Zero-day Exploits": {"atlas_id": "AML.T0001", "description": "AI systems have failure modes that are difficult to characterize and poorly understood. Continuous monitoring and red teaming critical.", "controls": {"Environment": ["CA-08-00","SI-02-00","SI-03-00"], "AI Platform": ["CA-08-00","SI-02-00","SI-03-00"], "AI Models": ["SI-20-00"], "AI Data": ["SI-20-00"]}, "residual_risk": "Given prevalence of unknown failure modes, no mitigation can eliminate all zero-day risk."},
    "Denial of Service": {"atlas_id": "AML.T0034", "description": "AI systems with expensive compute requirements are vulnerable to overloading. Adversaries flood with inputs or craft heavy queries.", "controls": {"Environment": ["SC-05-00","SC-37-00"], "AI Platform": ["SR-03-00","SR-11-00"], "AI Models": ["SR-03-00"]}, "residual_risk": "Some cost burden or service quality degradation cannot be compensated for."}
}

def get_atlas_context(query: str) -> str:
    """Build context string for Claude API from ATLAS/SAFE-AI knowledge base"""
    context_parts = []
    query_lower = query.lower()

    # Find matching techniques
    matched_techniques = []
    for tid, tech in ATLAS_TECHNIQUES.items():
        if (query_lower in tech["name"].lower() or
            query_lower in tech.get("description", "").lower() or
            tid.lower() in query_lower):
            matched_techniques.append((tid, tech))

    # Find matching threats
    matched_threats = []
    for tname, threat in SAFE_AI_THREATS.items():
        if (query_lower in tname.lower() or
            query_lower in threat.get("description", "").lower() or
            threat.get("atlas_id", "").lower() in query_lower):
            matched_threats.append((tname, threat))

    # Find matching tactics
    matched_tactics = []
    for tid, tactic in ATLAS_TACTICS.items():
        if (query_lower in tactic["name"].lower() or
            tid.lower() in query_lower):
            matched_tactics.append((tid, tactic))

    # Build context
    if matched_tactics:
        context_parts.append("=== MATCHING ATLAS TACTICS ===")
        for tid, tac in matched_tactics:
            context_parts.append(f"{tid} - {tac['name']}: {tac['description']}")

    if matched_techniques:
        context_parts.append("\n=== MATCHING ATLAS TECHNIQUES ===")
        for tid, tech in matched_techniques:
            shared = " [SHARED WITH ATT&CK]" if tech.get("attck_shared") else ""
            also = f" Also in: {', '.join(tech['also_in_tactics'])}" if tech.get("also_in_tactics") else ""
            controls = ""
            if tech.get("safe_ai_controls"):
                ctrl_parts = []
                for element, ctrls in tech["safe_ai_controls"].items():
                    ctrl_parts.append(f"{element}: {', '.join(ctrls)}")
                controls = f" SAFE-AI Controls: {'; '.join(ctrl_parts)}"
            context_parts.append(f"{tid} - {tech['name']}{shared}: {tech['description']}{also}{controls}")

    if matched_threats:
        context_parts.append("\n=== MATCHING SAFE-AI THREATS ===")
        for tname, threat in matched_threats:
            context_parts.append(f"\nThreat: {tname} (ATLAS: {threat['atlas_id']})")
            context_parts.append(f"Description: {threat['description']}")
            context_parts.append(f"Residual Risk: {threat['residual_risk']}")
            context_parts.append("NIST 800-53 Controls by System Element:")
            for element, ctrls in threat.get("controls", {}).items():
                context_parts.append(f"  {element}: {', '.join(ctrls)}")

    # If no direct matches, return full summary for Claude to reason over
    if not matched_techniques and not matched_threats and not matched_tactics:
        context_parts.append("=== ATLAS TACTICS (14 categories) ===")
        for tid, tac in ATLAS_TACTICS.items():
            context_parts.append(f"{tid} - {tac['name']}")
        context_parts.append("\n=== ALL ATLAS TECHNIQUES ===")
        for tid, tech in ATLAS_TECHNIQUES.items():
            shared = " &" if tech.get("attck_shared") else ""
            context_parts.append(f"{tid}{shared} - {tech['name']} ({tech['tactic']})")
        context_parts.append("\n=== ALL SAFE-AI THREATS ===")
        for tname, threat in SAFE_AI_THREATS.items():
            context_parts.append(f"{tname} ({threat['atlas_id']}): {threat['description'][:100]}...")

    return "\n".join(context_parts)
