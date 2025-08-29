# 🤖 AI Agent Configuration Guide for Penetration Testing

## Table of Contents
1. [Overview](#overview)
2. [Model Selection Guide](#model-selection-guide)
3. [Local Model Configuration](#local-model-configuration)
4. [System Prompt Engineering](#system-prompt-engineering)
5. [Advanced Configuration](#advanced-configuration)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

## Overview

The AI Agent serves as the central orchestrator for automated penetration testing operations. This comprehensive guide covers configuration, optimization, and troubleshooting for maximum effectiveness.

### What the AI Agent Does
- **Vulnerability Analysis**: Automated analysis of security findings
- **Attack Path Planning**: Intelligent sequencing of penetration testing tools
- **Risk Assessment**: Contextual risk scoring and prioritization
- **Report Generation**: Comprehensive security assessment documentation
- **Real-time Decision Making**: Dynamic adaptation based on findings

## Model Selection Guide

### Cloud-Based Models (Recommended for Production)

#### GPT-5 (Latest Flagship)
**Best For**: Complex analysis, comprehensive reporting, creative problem-solving
```yaml
Model: gpt-5-2025-08-07
Context Window: 200,000 tokens
Strengths:
  - Advanced reasoning capabilities
  - Comprehensive security knowledge
  - Excellent report generation
  - Creative attack vector identification
Expected Performance:
  - Response Time: 2-5 seconds
  - Accuracy: 95%+ for security analysis
  - Token Usage: ~1,500 tokens per analysis
```

**Example Configuration**:
```json
{
  "model": "gpt-5-2025-08-07",
  "temperature": 0.2,
  "maxTokens": 2000,
  "systemPrompt": "You are an expert cybersecurity AI agent...",
  "safetyLevel": "high"
}
```

**Expected Outcomes**:
- Detailed vulnerability analysis with CVSS scoring
- Contextual remediation recommendations
- Professional-grade reporting
- Creative but ethical attack scenarios

#### Claude Opus 4 (Most Capable)
**Best For**: Deep technical analysis, complex reasoning, compliance reporting
```yaml
Model: claude-opus-4-20250514
Context Window: 200,000 tokens
Strengths:
  - Superior reasoning for complex scenarios
  - Excellent compliance documentation
  - Detailed technical explanations
  - Strong ethical guardrails
Expected Performance:
  - Response Time: 3-6 seconds
  - Accuracy: 97%+ for technical analysis
  - Token Usage: ~1,200 tokens per analysis
```

#### GPT-4.1 (Reliable Performance)
**Best For**: Consistent operations, production environments, cost optimization
```yaml
Model: gpt-4.1-2025-04-14
Context Window: 128,000 tokens
Strengths:
  - Consistent performance
  - Lower cost per token
  - Proven reliability
  - Good security knowledge base
Expected Performance:
  - Response Time: 1-3 seconds
  - Accuracy: 92%+ for security analysis
  - Token Usage: ~1,000 tokens per analysis
```

### Reasoning Models (Advanced Analysis)

#### O3 (Most Powerful Reasoning)
**Use Cases**: 
- Complex multi-step attack chains
- Advanced threat modeling
- Deep vulnerability correlation
- Strategic security assessment planning

**Configuration Example**:
```json
{
  "enableReasoningMode": true,
  "reasoningModel": "o3-2025-04-16",
  "primaryModel": "gpt-5-2025-08-07",
  "temperature": 0.1
}
```

**Expected Performance**:
- Complex attack chain analysis in 10-15 seconds
- Multi-step reasoning with detailed explanations
- Advanced threat correlation capabilities
- Strategic security recommendations

#### O4 Mini (Fast Reasoning)
**Use Cases**:
- Real-time decision making
- Quick vulnerability correlation
- Automated tool selection
- Fast risk assessment

## Local Model Configuration

### Supported Providers

#### Ollama (Recommended for Local Deployment)
Ollama provides easy local model deployment with excellent performance.

**Installation & Setup**:
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Download security-focused models
ollama pull llama2
ollama pull codellama
ollama pull mistral
ollama pull neural-chat
```

**Configuration**:
```json
{
  "useLocalModel": true,
  "localModelConfig": {
    "provider": "ollama",
    "apiEndpoint": "http://localhost",
    "port": 11434,
    "modelName": "llama2",
    "timeout": 30000,
    "maxRetries": 3
  }
}
```

**Expected Performance**:
- Response Time: 5-15 seconds (depending on hardware)
- Privacy: Complete data privacy
- Cost: No per-token costs
- Offline: Works without internet connection

**Recommended Models for Security**:

1. **Llama 2 13B** (General Security Analysis)
   ```bash
   ollama pull llama2:13b
   ```
   - Good general security knowledge
   - Reasonable response times
   - Memory requirement: ~8GB RAM

2. **Code Llama 34B** (Code Security Review)
   ```bash
   ollama pull codellama:34b
   ```
   - Excellent for code vulnerability analysis
   - Strong programming language understanding
   - Memory requirement: ~20GB RAM

3. **Mistral 7B** (Fast Security Analysis)
   ```bash
   ollama pull mistral:7b
   ```
   - Fast response times
   - Good security awareness
   - Memory requirement: ~4GB RAM

#### LM Studio
Professional local model management with GUI interface.

**Configuration**:
```json
{
  "useLocalModel": true,
  "localModelConfig": {
    "provider": "lm-studio",
    "apiEndpoint": "http://localhost",
    "port": 1234,
    "modelName": "TheBloke/Llama-2-13B-Chat-GGML",
    "timeout": 45000,
    "maxRetries": 3
  }
}
```

**Advantages**:
- User-friendly GUI
- Model performance optimization
- Built-in model library
- Hardware acceleration support

#### Text Generation WebUI
Advanced local deployment for power users.

**Configuration**:
```json
{
  "useLocalModel": true,
  "localModelConfig": {
    "provider": "text-generation-webui",
    "apiEndpoint": "http://localhost",
    "port": 5000,
    "modelName": "llama-2-13b-chat",
    "apiKey": "optional-api-key",
    "timeout": 60000,
    "maxRetries": 5
  }
}
```

### Hardware Requirements

#### Minimum Requirements
- **RAM**: 8GB for 7B parameter models
- **Storage**: 10GB free space
- **CPU**: Modern multi-core processor
- **GPU**: Optional but recommended (NVIDIA with CUDA)

#### Recommended Requirements
- **RAM**: 16-32GB for 13B+ parameter models
- **Storage**: 50GB+ SSD storage
- **CPU**: 8+ core processor
- **GPU**: NVIDIA RTX 3080+ or equivalent

#### Performance Expectations

| Model Size | RAM Required | Response Time | Quality |
|------------|--------------|---------------|---------|
| 7B         | 6-8GB        | 2-5 seconds   | Good    |
| 13B        | 10-16GB      | 5-10 seconds  | Better  |
| 34B        | 20-32GB      | 10-20 seconds | Best    |

## System Prompt Engineering

### Preset Prompts

#### Penetration Testing Expert
**Use Case**: Professional security assessments, compliance testing
```
You are an expert AI cybersecurity agent specializing in penetration testing and vulnerability assessment. 

CORE EXPERTISE:
- OWASP Top 10 vulnerabilities
- Network security assessment
- Web application security testing
- Active Directory security
- Cloud security architecture
- Risk assessment and CVSS scoring

BEHAVIOR EXPECTATIONS:
- Provide detailed, actionable insights
- Maintain ethical and legal compliance
- Focus on business impact and remediation
- Use industry-standard terminology
- Include references to security frameworks

OUTPUT FORMAT:
- Clear executive summaries
- Technical details with evidence
- Step-by-step remediation guidance
- Risk prioritization matrices
- Compliance mapping (NIST, ISO 27001, etc.)

ETHICAL CONSTRAINTS:
- Only suggest authorized testing activities
- Emphasize proper documentation
- Highlight legal and regulatory considerations
- Recommend responsible disclosure practices
```

**Expected Outcomes**:
- Professional security assessment reports
- Detailed vulnerability analysis with CVSS scores
- Business-focused remediation recommendations
- Compliance-ready documentation

#### Red Team Operator
**Use Case**: Advanced offensive security, creative attack scenarios
```
You are an advanced red team operator with deep expertise in offensive security. 

SPECIALIZATIONS:
- Advanced persistent threat (APT) simulation
- Social engineering and phishing campaigns
- Physical security assessments
- Wireless security testing
- Mobile application security
- Cloud infrastructure penetration

APPROACH:
- Think like an adversary
- Focus on creative attack vectors
- Consider multi-stage attack chains
- Emphasize stealth and persistence
- Analyze defensive countermeasures

DELIVERABLES:
- Detailed attack narratives
- Time-based attack progression
- Evasion technique documentation
- Purple team collaboration insights
- Threat intelligence correlation

BOUNDARIES:
- All activities must remain within legal scope
- Emphasize authorized testing only
- Document all techniques for defensive improvement
- Maintain professional ethical standards
```

**Expected Outcomes**:
- Creative attack scenario development
- Advanced evasion technique identification
- Comprehensive attack chain analysis
- Purple team training materials

#### Compliance Expert
**Use Case**: Regulatory assessments, audit preparation, policy development
```
You are a cybersecurity compliance expert conducting authorized security assessments.

REGULATORY FRAMEWORKS:
- NIST Cybersecurity Framework
- ISO 27001/27002
- SOC 2 Type II
- PCI DSS
- HIPAA Security Rule
- GDPR Technical Safeguards

ASSESSMENT APPROACH:
- Control-based evaluation methodology
- Gap analysis and maturity assessment
- Risk quantification and heat mapping
- Policy and procedure review
- Technical control validation

DOCUMENTATION STANDARDS:
- Audit-ready evidence collection
- Control effectiveness ratings
- Remediation roadmaps with timelines
- Executive dashboard summaries
- Regulatory mapping matrices

COMPLIANCE FOCUS:
- Prioritize regulatory alignment
- Emphasize documentation completeness
- Include audit trail requirements
- Reference applicable standards
- Provide compliance status indicators
```

**Expected Outcomes**:
- Audit-ready assessment reports
- Regulatory compliance matrices
- Control effectiveness ratings
- Detailed remediation roadmaps

#### Beginner-Friendly Mentor
**Use Case**: Training, education, knowledge transfer
```
You are a patient cybersecurity mentor helping newcomers learn penetration testing.

TEACHING APPROACH:
- Explain concepts in simple terms
- Provide step-by-step guidance
- Include educational context and background
- Use analogies and real-world examples
- Emphasize safety and ethical practices

EDUCATIONAL CONTENT:
- Fundamental security concepts
- Tool usage explanations
- Methodology best practices
- Common pitfalls and how to avoid them
- Career development guidance

SAFETY EMPHASIS:
- Always stress legal and ethical boundaries
- Provide proper lab setup guidance
- Emphasize proper authorization
- Include responsible disclosure principles
- Highlight professional development paths

COMMUNICATION STYLE:
- Encouraging and supportive tone
- Clear, jargon-free explanations
- Progressive skill building
- Practical hands-on examples
- Community and resource recommendations
```

**Expected Outcomes**:
- Educational assessment reports
- Step-by-step learning materials
- Safety-focused guidance
- Skill development roadmaps

### Custom Prompt Creation Guidelines

#### Structure Template
```
ROLE DEFINITION:
[Define the AI's primary role and expertise]

CORE COMPETENCIES:
[List specific technical skills and knowledge areas]

METHODOLOGY:
[Describe the approach and thinking process]

OUTPUT SPECIFICATIONS:
[Define expected format and content structure]

ETHICAL BOUNDARIES:
[Specify legal and ethical constraints]

QUALITY STANDARDS:
[Define accuracy and professionalism expectations]
```

#### Example Custom Prompt: Cloud Security Specialist
```
ROLE DEFINITION:
You are a cloud security specialist focused on AWS, Azure, and GCP security assessments.

CORE COMPETENCIES:
- Cloud architecture security review
- Identity and Access Management (IAM) analysis
- Container and Kubernetes security
- Serverless security assessment
- Cloud compliance frameworks (CSA CCM, FedRAMP)
- Infrastructure as Code (IaC) security

METHODOLOGY:
- Follow cloud security best practices frameworks
- Analyze configuration drift and misconfigurations
- Assess cloud-native threat vectors
- Evaluate data protection and encryption
- Review network segmentation and access controls

OUTPUT SPECIFICATIONS:
- Cloud security posture summaries
- Configuration baseline recommendations
- Multi-cloud comparison matrices
- Cost-optimized security improvements
- Automation and tooling recommendations

ETHICAL BOUNDARIES:
- Respect cloud provider terms of service
- Ensure proper authorization for cloud assessments
- Protect sensitive cloud configuration data
- Follow responsible disclosure for cloud vulnerabilities

QUALITY STANDARDS:
- Reference current cloud security frameworks
- Provide cloud-native solution recommendations
- Include cost-benefit analysis for improvements
- Ensure scalability and automation considerations
```

## Advanced Configuration

### Temperature Settings Guide

#### Temperature: 0.0 - 0.3 (Highly Focused)
**Use Cases**: 
- Vulnerability scoring
- Compliance checking
- Factual reporting
- Technical documentation

**Example Configuration**:
```json
{
  "temperature": 0.2,
  "expectedBehavior": "Highly consistent, factual responses",
  "useFor": ["CVSS scoring", "Compliance reports", "Technical analysis"]
}
```

#### Temperature: 0.4 - 0.7 (Balanced)
**Use Cases**:
- Attack scenario planning
- Risk assessment narratives
- Remediation recommendations
- Executive summaries

#### Temperature: 0.8 - 1.0 (Creative)
**Use Cases**:
- Red team scenario development
- Creative attack vectors
- Social engineering scenarios
- Purple team exercises

### Response Format Configuration

#### Structured Format (Recommended)
```json
{
  "responseFormat": "structured",
  "benefits": [
    "Consistent output parsing",
    "Automated report generation",
    "API integration friendly",
    "Quality assurance compatible"
  ]
}
```

**Expected Output Structure**:
```json
{
  "executive_summary": "...",
  "technical_findings": [...],
  "risk_assessment": {...},
  "recommendations": [...],
  "compliance_mapping": {...}
}
```

#### JSON Format
```json
{
  "responseFormat": "json",
  "useCase": "API integration, automated processing",
  "structure": "Fully machine-readable output"
}
```

#### Text Format
```json
{
  "responseFormat": "text",
  "useCase": "Human-readable reports, presentations",
  "structure": "Natural language output"
}
```

### Safety Level Configuration

#### High Safety (Recommended for Production)
- Strict ethical guardrails
- Conservative recommendations
- Emphasis on legal compliance
- Detailed risk warnings

#### Medium Safety
- Balanced approach
- More detailed technical explanations
- Moderate risk scenarios
- Standard compliance references

#### Low Safety (Advanced Users Only)
- Detailed technical information
- Advanced attack scenarios
- Minimal content filtering
- Expert-level assumptions

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Model Not Responding"
**Symptoms**: Timeouts, no response from AI agent
**Solutions**:
1. Check network connectivity
2. Verify API endpoint configuration
3. Increase timeout values
4. Test with fallback model

**Diagnostic Commands**:
```bash
# Test Ollama connection
curl http://localhost:11434/api/version

# Test LM Studio connection
curl http://localhost:1234/v1/models

# Check system resources
htop
nvidia-smi (for GPU models)
```

#### Issue: "Poor Response Quality"
**Symptoms**: Irrelevant responses, low accuracy
**Solutions**:
1. Adjust temperature settings
2. Refine system prompt
3. Increase max tokens
4. Switch to more capable model

**Optimization Steps**:
```json
{
  "troubleshooting": {
    "lowQuality": {
      "checkTemperature": "Reduce to 0.2-0.3 for factual content",
      "reviewPrompt": "Ensure specific domain expertise",
      "increaseTokens": "Allow longer, more detailed responses",
      "upgradeModel": "Use more capable model for complex tasks"
    }
  }
}
```

#### Issue: "Slow Response Times"
**Symptoms**: Long delays, timeouts
**Solutions**:
1. Optimize hardware resources
2. Use smaller models for simple tasks
3. Implement response caching
4. Configure load balancing

### Performance Optimization

#### Model Selection Matrix
| Task Complexity | Recommended Model | Expected Response Time |
|-----------------|-------------------|----------------------|
| Simple Analysis | GPT-5 Mini        | 1-2 seconds         |
| Standard Assessment | GPT-4.1        | 2-4 seconds         |
| Complex Analysis | GPT-5            | 3-6 seconds         |
| Deep Reasoning  | O3 + GPT-5       | 8-15 seconds        |

#### Hardware Optimization
```yaml
CPU Optimization:
  - Use multi-core processors
  - Enable hyperthreading
  - Monitor CPU temperature
  - Allocate sufficient RAM

GPU Acceleration:
  - NVIDIA CUDA support
  - Sufficient VRAM (8GB+)
  - Updated drivers
  - Proper cooling

Storage Optimization:
  - SSD for model storage
  - Fast I/O for temporary files
  - Sufficient free space
  - Regular cleanup
```

## Best Practices

### Security Considerations
1. **API Key Management**: Store securely, rotate regularly
2. **Network Security**: Use HTTPS, VPN for remote access
3. **Data Privacy**: Ensure sensitive data protection
4. **Access Control**: Implement proper authentication
5. **Audit Logging**: Maintain comprehensive logs

### Operational Excellence
1. **Monitoring**: Implement health checks and alerting
2. **Backup**: Regular configuration backups
3. **Documentation**: Maintain current configurations
4. **Testing**: Regular functionality testing
5. **Updates**: Keep models and configurations current

### Cost Optimization
1. **Model Selection**: Choose appropriate capability level
2. **Token Management**: Optimize prompt length
3. **Caching**: Implement response caching
4. **Batching**: Process multiple requests efficiently
5. **Monitoring**: Track usage and costs

## Conclusion

Proper AI Agent configuration is crucial for effective automated penetration testing. This guide provides comprehensive coverage of all configuration aspects, from basic model selection to advanced optimization techniques.

For additional support and updates, refer to:
- [API Configuration Guide](./API_CONFIGURATION_GUIDE.md)
- [Penetration Testing Methodologies](./PENTEST_METHODOLOGIES.md)
- [Troubleshooting Handbook](./TROUBLESHOOTING_HANDBOOK.md)

---
*Last Updated: December 2024*
*Version: 2.0.0*