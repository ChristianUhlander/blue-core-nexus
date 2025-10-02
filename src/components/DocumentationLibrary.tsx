import React, { useState } from 'react';
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle 
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import {
  Search,
  BookOpen,
  Code,
  AlertTriangle,
  Target,
  Rocket,
  Shield,
  Settings,
  Database,
  Globe,
  Lock,
  Eye,
  Brain,
  CheckCircle,
  Clock,
  Star,
  Download,
  ExternalLink,
  Copy,
  Bookmark,
  BookmarkCheck,
  ChevronRight,
  ChevronDown,
  Filter,
  Home,
  FolderOpen,
  FileText
} from 'lucide-react';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

interface DocumentationLibraryProps {
  onClose: () => void;
}

interface DocSection {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  items: DocItem[];
}

interface DocItem {
  id: string;
  title: string;
  description: string;
  type: 'guide' | 'tutorial' | 'reference' | 'faq' | 'api';
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: string;
  content: string;
  codeExamples?: CodeExample[];
  prerequisites?: string[];
  expectedOutcomes?: string[];
  qaSteps?: QAStep[];
  troubleshootingTips?: string[];
  tags?: string[];
  lastUpdated?: string;
}

interface CodeExample {
  title: string;
  language: string;
  code: string;
  explanation: string;
}

interface QAStep {
  step: string;
  expectedResult: string;
  troubleshooting?: string;
}

export const DocumentationLibrary: React.FC<DocumentationLibraryProps> = ({ onClose }) => {
  const { toast } = useToast();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSection, setSelectedSection] = useState('getting-started');
  const [selectedDoc, setSelectedDoc] = useState<string | null>(null);
  const [bookmarkedDocs, setBookmarkedDocs] = useState<string[]>([]);
  const [expandedSections, setExpandedSections] = useState<string[]>(['getting-started']);
  const [filterType, setFilterType] = useState<string>('all');
  const [filterDifficulty, setFilterDifficulty] = useState<string>('all');

  // Comprehensive documentation sections with same content as before
  const documentationSections: DocSection[] = [
    {
      id: 'getting-started',
      title: 'Getting Started',
      description: 'Quick start guides and basic setup',
      icon: Rocket,
      badge: 'Essential',
      items: [
        {
          id: 'quick-start',
          title: 'Quick Start Guide',
          description: 'Get up and running in 5 minutes',
          type: 'tutorial',
          difficulty: 'beginner',
          estimatedTime: '5 minutes',
          content: `# Quick Start Guide

## Overview
The IPS Security Center provides comprehensive security monitoring and penetration testing capabilities through an intuitive web interface.

## Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Network access to security services
- Basic understanding of cybersecurity concepts

## Step 1: Access the Platform
1. Navigate to the IPS Security Center URL
2. The dashboard will automatically load and begin health checks
3. Wait for service initialization (30-60 seconds)

## Step 2: Service Verification
The platform will automatically check:
- **Wazuh SIEM**: Security event monitoring
- **OpenVAS/GVM**: Vulnerability assessment
- **OWASP ZAP**: Web application security testing
- **SpiderFoot**: OSINT intelligence gathering

## Step 3: Dashboard Overview
Key sections available:
- **Real-time Monitoring**: Live security events and alerts
- **Vulnerability Management**: Scan results and remediation
- **Penetration Testing**: Automated and manual testing tools
- **Intelligence Gathering**: OSINT and threat intelligence

## Next Steps
- Review the System Architecture guide
- Configure your first security scan
- Set up monitoring and alerting preferences`,
          prerequisites: ['Modern web browser', 'Network connectivity'],
          expectedOutcomes: [
            'Successfully access the platform',
            'Understand the main interface components',
            'Verify all services are operational'
          ]
        },
        {
          id: 'architecture-overview',
          title: 'System Architecture Overview',
          description: 'Understanding the platform architecture and components',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '15 minutes',
          content: `# System Architecture Overview

## High-Level Architecture

The IPS Security Center follows a microservices architecture with clear separation of concerns:

### Frontend Layer
- **React Application**: Modern single-page application
- **Real-time WebSocket**: Live updates and notifications
- **Responsive Design**: Works on desktop and mobile devices

### Security Services Layer
- **Wazuh SIEM**: Security information and event management
- **OpenVAS/GVM**: Vulnerability assessment and management  
- **OWASP ZAP**: Web application security testing
- **SpiderFoot**: Open source intelligence gathering

### Integration Layer
- **Security API Gateway**: Unified API access to all services
- **Authentication Service**: User management and access control
- **Event Bus**: Real-time event distribution
- **Data Aggregation**: Centralized security data processing

### Data Layer
- **Time-series Database**: Security metrics and events
- **Document Store**: Vulnerability and scan results
- **Configuration Database**: System and user settings
- **Audit Logs**: Compliance and forensic data

## Security Model
- **Zero Trust Architecture**: All communications are encrypted and authenticated
- **Role-Based Access Control**: Granular permissions based on user roles
- **Audit Logging**: Complete trail of all security activities
- **Network Segmentation**: Services isolated in secure network zones`,
          prerequisites: ['Basic understanding of cybersecurity concepts', 'Familiarity with web applications'],
          expectedOutcomes: [
            'Understand the overall system architecture',
            'Know how different components interact',
            'Grasp the security model and data flow',
            'Identify integration points for custom tools'
          ]
        }
      ]
    },
    {
      id: 'osint-mastery',
      title: 'OSINT Mastery',
      description: 'Open Source Intelligence gathering techniques',
      icon: Search,
      badge: 'Updated 2024',
      items: [
        {
          id: 'osint-methodology',
          title: 'OSINT Methodology & Best Practices',
          description: 'Comprehensive guide to professional OSINT investigation techniques',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '45 minutes',
          content: `# OSINT Methodology & Best Practices 2024

## Intelligence Collection Framework

### Phase 1: Planning & Direction
- **Define Objectives**: Clear intelligence requirements
- **Scope Definition**: Boundaries and limitations
- **Legal Compliance**: Ensure all activities are legal and ethical
- **Resource Allocation**: Tools, time, and personnel

### Phase 2: Collection
- **Passive Collection**: No direct interaction with targets
- **Active Collection**: Controlled interaction when necessary
- **Multi-source Verification**: Cross-reference information
- **Chain of Custody**: Maintain evidence integrity

### Phase 3: Processing & Analysis
- **Data Normalization**: Standardize collected information
- **Correlation Analysis**: Identify patterns and connections
- **Confidence Assessment**: Rate reliability of sources
- **Timeline Construction**: Chronological event mapping

### Phase 4: Dissemination
- **Report Generation**: Professional intelligence products
- **Stakeholder Communication**: Appropriate audience targeting
- **Secure Distribution**: Protect sensitive information
- **Feedback Collection**: Improve future operations

## Advanced OSINT Techniques

### Social Media Intelligence (SOCMINT)
\`\`\`bash
# Example: Twitter Intelligence Gathering
# Tools: TweetDeck, Social-Searcher, Twint
python3 -m twint -u target_username --limit 100 --csv
\`\`\`

### Domain Intelligence (DOMINT)
\`\`\`bash
# Subdomain enumeration
subfinder -d target.com | httprobe | tee live_subdomains.txt

# DNS reconnaissance
dig +trace target.com
nslookup -type=MX target.com
\`\`\`

### Legal & Ethical Considerations
- **GDPR Compliance**: Data protection regulations
- **Terms of Service**: Respect platform policies
- **Attribution**: Proper source citation
- **Privacy Protection**: Minimize personal data exposure`,
          prerequisites: ['Basic OSINT knowledge', 'Understanding of legal frameworks'],
          expectedOutcomes: [
            'Master professional OSINT methodology',
            'Implement quality assurance processes',
            'Ensure legal and ethical compliance',
            'Produce high-quality intelligence reports'
          ]
        }
      ]
    },
    {
      id: 'penetration-testing',
      title: 'Penetration Testing',
      description: 'Comprehensive penetration testing methodologies',
      icon: Target,
      badge: 'Core',
      items: [
        {
          id: 'pentest-methodology',
          title: 'Penetration Testing Methodology',
          description: 'OWASP and NIST-based penetration testing framework',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '60 minutes',
          content: `# Penetration Testing Methodology

## PTES (Penetration Testing Execution Standard)

### 1. Pre-engagement Interactions
- **Scope Definition**: Clear boundaries and objectives
- **Rules of Engagement**: Authorized activities and limitations
- **Legal Agreements**: Contracts and liability protection
- **Communication Plan**: Reporting structure and escalation

### 2. Intelligence Gathering
- **Passive Reconnaissance**: OSINT without target interaction
- **Active Reconnaissance**: Direct target engagement
- **Infrastructure Mapping**: Network topology discovery
- **Service Identification**: Running services and versions

### 3. Threat Modeling
- **Attack Surface Analysis**: Entry points identification
- **Vulnerability Assessment**: Weakness discovery
- **Risk Prioritization**: Impact and likelihood scoring
- **Attack Path Planning**: Exploitation strategy

### 4. Vulnerability Analysis
- **Automated Scanning**: Tools-based discovery
- **Manual Testing**: Human verification and validation
- **False Positive Elimination**: Result accuracy
- **Exploitation Feasibility**: Practical attack assessment

### 5. Exploitation
- **Initial Compromise**: Gaining foothold
- **Privilege Escalation**: Expanding access rights
- **Lateral Movement**: Network traversal
- **Persistence**: Maintaining access

### 6. Post Exploitation
- **Data Collection**: Evidence gathering
- **Impact Assessment**: Business risk evaluation
- **Cleanup**: Removing traces and restoring systems
- **Documentation**: Detailed findings recording

### 7. Reporting
- **Executive Summary**: High-level business impact
- **Technical Details**: Vulnerability specifics
- **Remediation Guidance**: Fix recommendations
- **Risk Ratings**: CVSS-based scoring`,
          prerequisites: ['Advanced security knowledge', 'Penetration testing experience'],
          expectedOutcomes: [
            'Understand complete testing methodology',
            'Execute professional penetration tests',
            'Produce comprehensive reports',
            'Maintain ethical and legal compliance'
          ]
        }
      ]
    },
    {
      id: 'vulnerability-management',
      title: 'Vulnerability Management',
      description: 'Comprehensive vulnerability assessment and management',
      icon: Shield,
      badge: 'Critical',
      items: [
        {
          id: 'vuln-scanning',
          title: 'Vulnerability Scanning Best Practices',
          description: 'Professional vulnerability assessment methodologies',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '30 minutes',
          content: `# Vulnerability Scanning Best Practices

## Scanning Strategy

### 1. Asset Discovery
- **Network Discovery**: Identify live hosts and services
- **Service Enumeration**: Catalog running services
- **Asset Classification**: Categorize by business importance
- **Baseline Establishment**: Normal state documentation

### 2. Vulnerability Assessment
- **Authenticated Scans**: Credentialed assessments
- **Unauthenticated Scans**: External perspective
- **Web Application Testing**: OWASP Top 10 coverage
- **Database Security**: SQL injection and config issues

### 3. Risk Analysis
- **CVSS Scoring**: Standardized vulnerability rating
- **Business Context**: Asset importance consideration
- **Threat Intelligence**: Active exploit availability
- **Compensating Controls**: Mitigation factor analysis

### 4. Remediation Planning
- **Priority Matrix**: Risk-based prioritization
- **Patch Management**: Update deployment strategy
- **Configuration Hardening**: Security baseline implementation
- **Workaround Solutions**: Temporary risk mitigation`,
          prerequisites: ['Basic security knowledge', 'Network understanding'],
          expectedOutcomes: [
            'Execute effective vulnerability scans',
            'Analyze and prioritize findings',
            'Develop remediation strategies',
            'Maintain security posture'
          ]
        }
      ]
    },
    {
      id: 'local-ai-deployment',
      title: 'Local AI Deployment',
      description: 'Deploy and configure local LLM models for security operations',
      icon: Brain,
      badge: 'AI/ML',
      items: [
        {
          id: 'lm-studio-setup',
          title: 'LM Studio Setup & Configuration Guide',
          description: 'Complete guide to setting up LM Studio for local LLM deployment in penetration testing',
          type: 'tutorial',
          difficulty: 'intermediate',
          estimatedTime: '30 minutes',
          content: `# LM Studio Setup & Configuration Guide

## Overview

LM Studio is a desktop application that makes running large language models (LLMs) locally simple and accessible. Unlike cloud-based solutions, LM Studio gives you complete control, privacy, and offline capabilities for your AI-powered security operations.

### Why Use LM Studio for Security?

- **Data Privacy**: All data stays on your infrastructure
- **Offline Operations**: No internet dependency for sensitive engagements
- **Cost Control**: No per-token API fees
- **Customization**: Full control over model selection and parameters
- **Compliance**: Meet strict data residency requirements

## System Requirements

### Minimum Requirements
- **CPU**: 8-core processor (Intel i7/AMD Ryzen 7 or better)
- **RAM**: 16 GB DDR4
- **Storage**: 50 GB free space (SSD recommended)
- **OS**: Windows 10/11, macOS 12+, Linux (Ubuntu 20.04+)

### Recommended Configuration
- **CPU**: 12+ core processor with AVX2 support
- **RAM**: 32 GB+ DDR4/DDR5
- **GPU**: NVIDIA RTX 3060+ (12GB+ VRAM) or AMD RX 6800+
- **Storage**: 200 GB NVMe SSD
- **OS**: Latest stable version

### GPU Acceleration (Optional but Recommended)
- **NVIDIA**: CUDA 11.8+ compatible GPU with 8GB+ VRAM
- **AMD**: ROCm compatible GPU (Linux only)
- **Apple Silicon**: M1/M2/M3 chips with Metal acceleration

## Installation Guide

### Step 1: Download LM Studio

1. Visit the official website: **https://lmstudio.ai**
2. Click "Download for [Your OS]"
3. Choose the appropriate installer:
   - **Windows**: \`.exe\` installer
   - **macOS**: \`.dmg\` disk image
   - **Linux**: \`.AppImage\` or \`.deb\` package

### Step 2: Install LM Studio

#### Windows Installation
\`\`\`powershell
# Run the downloaded installer
# Follow the installation wizard
# Choose installation directory (default: C:\\Program Files\\LM Studio)
# Select "Create desktop shortcut" for easy access
\`\`\`

#### macOS Installation
\`\`\`bash
# Open the .dmg file
# Drag LM Studio to Applications folder
# First launch: System Preferences → Security → Allow LM Studio
\`\`\`

#### Linux Installation (AppImage)
\`\`\`bash
# Make the AppImage executable
chmod +x LM-Studio-*.AppImage

# Run LM Studio
./LM-Studio-*.AppImage

# Optional: Create desktop shortcut
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/lmstudio.desktop << EOF
[Desktop Entry]
Name=LM Studio
Exec=/path/to/LM-Studio.AppImage
Type=Application
Icon=/path/to/icon.png
EOF
\`\`\`

### Step 3: First Launch Configuration

1. **Launch LM Studio** from Applications/Start Menu
2. **Accept License Agreement** and privacy policy
3. **Choose Model Storage Location**
   - Default: \`~/lm-studio/models\`
   - Recommended: Dedicated SSD with ample space
4. **Configure Hardware Acceleration**
   - Auto-detect available GPUs
   - Choose CPU-only or GPU-accelerated mode

## Model Selection for Security Operations

### Recommended Models for Penetration Testing

#### 1. **Code Llama 13B** (Best for Code Analysis)
- **Size**: 7.37 GB (quantized)
- **Use Case**: Vulnerability detection, code review
- **Context Window**: 16K tokens
- **Download**: Search "CodeLlama-13B-Instruct-GGUF" in LM Studio

#### 2. **Mistral 7B Instruct** (Best All-Rounder)
- **Size**: 4.37 GB (Q4 quantization)
- **Use Case**: General security tasks, report generation
- **Context Window**: 32K tokens
- **Download**: Search "Mistral-7B-Instruct-v0.2-GGUF"

#### 3. **Llama 3 8B** (Latest Technology)
- **Size**: 4.92 GB (Q4 quantization)
- **Use Case**: Advanced reasoning, multi-step analysis
- **Context Window**: 8K tokens
- **Download**: Search "Meta-Llama-3-8B-Instruct-GGUF"

#### 4. **DeepSeek Coder 6.7B** (Specialized Security)
- **Size**: 3.82 GB
- **Use Case**: Code vulnerability scanning, exploit development
- **Context Window**: 16K tokens
- **Download**: Search "DeepSeek-Coder-6.7B-Instruct-GGUF"

### Model Quantization Guide

Quantization reduces model size while maintaining quality:

- **Q2**: 2-bit (smallest, lowest quality) - Not recommended
- **Q4**: 4-bit (good balance) - **RECOMMENDED for most users**
- **Q5**: 5-bit (better quality, larger size)
- **Q8**: 8-bit (highest quality, largest size) - Recommended if you have resources

**Rule of thumb**: Start with Q4, upgrade to Q5/Q8 if quality is insufficient.

## Downloading Your First Model

### Step-by-Step Download Process

1. **Open LM Studio** and click the "Search" icon (magnifying glass)

2. **Search for a model**: Type "Mistral-7B-Instruct"

3. **Browse available versions**:
   - Look for "GGUF" format (required for LM Studio)
   - Check quantization levels (Q4_K_M recommended)
   - Review model size vs. your available storage

4. **Download the model**:
   - Click the download button next to your chosen version
   - Monitor download progress (typically 5-10 minutes)
   - Models are stored in your configured models directory

5. **Verify download**:
   - Check "Local Models" tab
   - Confirm model appears in the list
   - Note the model path for API integration

### Multiple Model Management

\`\`\`bash
# Models are stored in structured directories
~/lm-studio/models/
├── TheBloke/
│   ├── Mistral-7B-Instruct-v0.2-GGUF/
│   └── CodeLlama-13B-Instruct-GGUF/
└── meta-llama/
    └── Meta-Llama-3-8B-Instruct-GGUF/
\`\`\`

## API Server Configuration

### Starting the Local API Server

LM Studio provides an **OpenAI-compatible API** for easy integration.

#### Step 1: Load a Model

1. Go to "Local Models" tab
2. Click "Load" on your chosen model
3. Wait for model initialization (20-60 seconds)
4. Status will show "Model loaded successfully"

#### Step 2: Configure Server Settings

1. Click the **"Local Server"** tab
2. Configure server parameters:

\`\`\`json
{
  "host": "127.0.0.1",           // localhost only (secure)
  "port": 1234,                   // default port
  "cors": true,                   // enable for web apps
  "max_requests": 10,             // concurrent requests
  "context_length": 4096          // adjust based on model
}
\`\`\`

#### Step 3: Start the Server

1. Click **"Start Server"** button
2. Server status will show "Running"
3. API endpoint: \`http://localhost:1234/v1\`
4. Test with provided curl command

### API Testing

Test your server with a simple curl command:

\`\`\`bash
curl http://localhost:1234/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "mistral-7b-instruct",
    "messages": [
      {"role": "system", "content": "You are a cybersecurity expert."},
      {"role": "user", "content": "Explain SQL injection in simple terms."}
    ],
    "temperature": 0.7,
    "max_tokens": 500
  }'
\`\`\`

### Expected Response

\`\`\`json
{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "created": 1699000000,
  "model": "mistral-7b-instruct",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "SQL injection is a web security vulnerability..."
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 25,
    "completion_tokens": 150,
    "total_tokens": 175
  }
}
\`\`\`

## Integration with IPS Security Center

### Backend Integration (Python)

\`\`\`python
import requests

class LMStudioClient:
    def __init__(self, base_url="http://localhost:1234/v1"):
        self.base_url = base_url
        
    def analyze_vulnerability(self, code_snippet: str) -> dict:
        """Analyze code for security vulnerabilities"""
        response = requests.post(
            f"{self.base_url}/chat/completions",
            json={
                "model": "codellama-13b-instruct",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security code reviewer. Identify vulnerabilities."
                    },
                    {
                        "role": "user", 
                        "content": f"Review this code for security issues:\\n\\n{code_snippet}"
                    }
                ],
                "temperature": 0.3,  # Low temperature for consistent analysis
                "max_tokens": 1000
            }
        )
        return response.json()

# Usage
client = LMStudioClient()
result = client.analyze_vulnerability("""
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)
""")
print(result['choices'][0]['message']['content'])
\`\`\`

### Frontend Integration (TypeScript/React)

\`\`\`typescript
// services/lmStudioService.ts
export interface LMStudioMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export class LMStudioService {
  private apiUrl = 'http://localhost:1234/v1';
  
  async generateSecurityReport(findings: any[]): Promise<string> {
    const response = await fetch(\`\${this.apiUrl}/chat/completions\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'mistral-7b-instruct',
        messages: [
          {
            role: 'system',
            content: 'You are a security report writer. Create clear, actionable reports.'
          },
          {
            role: 'user',
            content: \`Generate an executive summary for these findings: \${JSON.stringify(findings)}\`
          }
        ],
        temperature: 0.5,
        max_tokens: 2000
      })
    });
    
    const data = await response.json();
    return data.choices[0].message.content;
  }
}
\`\`\`

## Performance Optimization

### GPU Acceleration Setup

#### NVIDIA GPUs (CUDA)
\`\`\`bash
# Verify CUDA installation
nvidia-smi

# LM Studio will automatically detect and use GPU
# Monitor GPU usage during inference
watch -n 1 nvidia-smi
\`\`\`

#### Apple Silicon (Metal)
- Automatic acceleration on M1/M2/M3 chips
- No additional configuration needed
- Monitor activity with Activity Monitor

### Memory Management

Adjust these settings in LM Studio → Preferences:

- **GPU Layers**: Number of model layers on GPU (higher = faster, more VRAM)
  - Start with 32, increase until VRAM limit reached
  - Monitor with \`nvidia-smi\` or Task Manager

- **Context Size**: Maximum conversation history
  - Default: 2048 tokens
  - Security reports: 4096+ tokens recommended

- **Batch Size**: Inference batch processing
  - CPU: 512
  - GPU: 2048+

### Performance Benchmarks

Expected generation speeds (tokens/second):

| Hardware | Q4 Model | Q8 Model |
|----------|----------|----------|
| CPU Only (16GB) | 3-8 t/s | 1-4 t/s |
| RTX 3060 (12GB) | 25-40 t/s | 15-25 t/s |
| RTX 4090 (24GB) | 80-120 t/s | 50-80 t/s |
| M2 Max (32GB) | 35-55 t/s | 20-35 t/s |

## Troubleshooting

### Common Issues

#### Model Won't Load
\`\`\`
Error: Failed to load model

Solutions:
1. Check available RAM (need 2x model size)
2. Verify GGUF format (not .bin or .pt)
3. Redownload potentially corrupted model
4. Update LM Studio to latest version
\`\`\`

#### Slow Inference Speed
\`\`\`
Solutions:
1. Enable GPU acceleration in Settings
2. Reduce context window size
3. Use lower quantization (Q4 vs Q8)
4. Close background applications
5. Increase batch size for GPUs
\`\`\`

#### API Connection Refused
\`\`\`
Error: Connection refused at localhost:1234

Solutions:
1. Verify server is running (check status indicator)
2. Confirm port 1234 isn't blocked by firewall
3. Check model is loaded before starting server
4. Review server logs for specific errors
\`\`\`

#### Out of Memory Errors
\`\`\`
Error: CUDA out of memory / Insufficient RAM

Solutions:
1. Use smaller model (7B vs 13B)
2. Lower GPU layers setting
3. Reduce context window
4. Use more aggressive quantization (Q4 vs Q8)
5. Close other GPU-intensive applications
\`\`\`

## Security Considerations

### Network Security
\`\`\`bash
# Bind to localhost only (default - secure)
host: 127.0.0.1

# If remote access needed, use SSH tunneling instead
ssh -L 1234:localhost:1234 user@remote-server

# Never expose directly to internet without authentication
\`\`\`

### Access Control
- LM Studio doesn't include built-in authentication
- Use reverse proxy (nginx) for production deployments
- Implement API key validation in your application layer

### Data Privacy
- All processing happens locally - no data sent to cloud
- Models don't retain conversation history between sessions
- Review model licenses for commercial use restrictions

## Advanced Configuration

### Custom Model Prompts

Create specialized security prompts:

\`\`\`json
{
  "system_prompts": {
    "vuln_scanner": "You are an expert vulnerability scanner. Analyze code for OWASP Top 10 issues. Be precise and provide CVE references.",
    "report_writer": "You are a technical security report writer. Use clear language for executive audiences. Include severity ratings.",
    "incident_responder": "You are an incident response expert. Provide immediate actionable steps, then detailed analysis."
  }
}
\`\`\`

### Model Comparison Testing

Test multiple models for your use case:

\`\`\`python
models = ["mistral-7b", "codellama-13b", "llama3-8b"]
test_prompt = "Identify vulnerabilities in this SQL query..."

for model in models:
    start_time = time.time()
    response = client.query(model, test_prompt)
    duration = time.time() - start_time
    
    print(f"{model}: {duration:.2f}s - Quality: {rate_quality(response)}")
\`\`\`

## Production Deployment

### Docker Deployment

\`\`\`dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \\
    curl \\
    wget \\
    build-essential

# Install LM Studio CLI (if available) or use llama.cpp
# Download models during build or mount as volume

EXPOSE 1234
CMD ["lm-studio-server", "--host", "0.0.0.0", "--port", "1234"]
\`\`\`

### Kubernetes Deployment

\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lm-studio
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: lm-studio
        image: lm-studio:latest
        resources:
          requests:
            memory: "16Gi"
            nvidia.com/gpu: 1
          limits:
            memory: "32Gi"
            nvidia.com/gpu: 1
        ports:
        - containerPort: 1234
\`\`\`

## Next Steps

1. **Experiment with Models**: Download 2-3 models and compare performance
2. **Integrate with Tools**: Connect to your existing security tools
3. **Optimize Performance**: Fine-tune settings for your hardware
4. **Create Workflows**: Build automated security analysis pipelines
5. **Monitor Usage**: Track performance metrics and costs

## Resources

- **Official Documentation**: https://lmstudio.ai/docs
- **Model Repository**: https://huggingface.co/models?library=gguf
- **Community Discord**: https://discord.gg/lmstudio
- **GitHub Issues**: Report bugs and request features

## Conclusion

LM Studio provides a powerful, privacy-focused platform for running local LLMs in security operations. With proper configuration and model selection, you can achieve performance comparable to cloud services while maintaining complete control over your data and processes.`,
          prerequisites: [
            'Basic understanding of AI/LLM concepts',
            'Command line familiarity',
            'Network configuration knowledge'
          ],
          expectedOutcomes: [
            'Successfully install and configure LM Studio',
            'Download and run security-focused models',
            'Set up local API server for integration',
            'Optimize performance for your hardware',
            'Integrate with IPS Security Center'
          ],
          tags: ['ai', 'llm', 'local-deployment', 'lm-studio', 'privacy'],
          lastUpdated: '2025-01-15'
        }
      ]
    },
    {
      id: 'backend-development',
      title: 'Backend Development',
      description: 'Backend architecture and development guides',
      icon: Database,
      badge: 'Developer',
      items: [
        {
          id: 'reporting-system-backend',
          title: 'Reporting System Backend Logic',
          description: 'Complete backend implementation guide for the intelligent reporting system',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '90 minutes',
          content: `# Reporting System Backend Logic Guide

## Overview

The Intelligent Reporting System generates AI-powered security reports tailored to different audiences (executives, technical teams, compliance officers). This guide outlines the backend architecture, data flow, and API design needed to support this functionality.

## Core Components Architecture

### 1. Report Generation Pipeline

\`\`\`
Data Collection → Online Research → Content Adaptation → Report Formatting → Delivery
\`\`\`

### 2. Key Data Structures

#### ReportTemplate
\`\`\`typescript
interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: string[];
  format: 'executive' | 'technical' | 'compliance';
  customizable: boolean;
}
\`\`\`

#### AudienceProfile  
\`\`\`typescript
interface AudienceProfile {
  id: string;
  name: string;
  type: 'executive' | 'technical' | 'compliance' | 'custom';
  description: string;
  focusAreas: string[];
  technicalLevel: 'low' | 'medium' | 'high';
  preferredFormat: string;
}
\`\`\`

#### ReportData
\`\`\`typescript
interface ReportData {
  vulnerabilities: SecurityVulnerability[];
  scanResults: ScanResult[];
  complianceStatus: ComplianceCheck[];
  metrics: SecurityMetrics;
  trends: TrendData[];
  recommendations: Recommendation[];
}
\`\`\`

## Required Backend APIs

### 1. Report Management Endpoints

#### \`POST /api/reports/generate\`
**Purpose**: Initiate report generation process
\`\`\`json
{
  "templateId": "string",
  "audienceId": "string", 
  "title": "string",
  "customInstructions": "string",
  "includeResearch": boolean,
  "researchQuery": "string",
  "llmConfig": {
    "provider": "openai|perplexity",
    "model": "string",
    "temperature": number,
    "maxTokens": number
  }
}
\`\`\`

**Response**: 
\`\`\`json
{
  "jobId": "string",
  "status": "initiated",
  "estimatedCompletion": "ISO8601"
}
\`\`\`

#### \`GET /api/reports/status/{jobId}\`
**Purpose**: Check report generation progress
\`\`\`json
{
  "jobId": "string",
  "status": "initiated|collecting|researching|generating|formatting|completed|failed",
  "progress": number,
  "currentStep": "string",
  "estimatedTimeRemaining": number,
  "error": "string|null"
}
\`\`\`

#### \`GET /api/reports/{jobId}\`
**Purpose**: Retrieve generated report
\`\`\`json
{
  "id": "string",
  "title": "string",
  "content": "string",
  "format": "markdown|html|pdf",
  "metadata": {
    "generatedAt": "ISO8601",
    "template": "string",
    "audience": "string",
    "dataSource": "string[]"
  }
}
\`\`\`

### 2. Data Collection Endpoints

#### \`GET /api/security/data\`
**Purpose**: Aggregate security data for reports
\`\`\`json
{
  "vulnerabilities": [],
  "scanResults": [],
  "complianceStatus": [],
  "metrics": {},
  "timeRange": {
    "start": "ISO8601",
    "end": "ISO8601"
  }
}
\`\`\`

### 3. Research Integration Endpoints

#### \`POST /api/research/query\`
**Purpose**: Conduct online security research
\`\`\`json
{
  "query": "string",
  "sources": ["perplexity", "nvd", "mitre"],
  "maxResults": number
}
\`\`\`

## Backend Logic Implementation

### 1. Report Generation Workflow

\`\`\`python
class ReportGenerationService:
    async def generate_report(self, request: ReportGenerationRequest) -> str:
        """
        Main report generation orchestrator
        """
        job_id = self.create_job(request)
        
        # Step 1: Data Collection (20% progress)
        await self.update_progress(job_id, 20, "Collecting security data")
        report_data = await self.gather_security_data(request.time_range)
        
        # Step 2: Online Research (40% progress) 
        if request.include_research:
            await self.update_progress(job_id, 40, "Conducting research")
            research_data = await self.conduct_research(request.research_query)
            report_data.research = research_data
            
        # Step 3: Content Generation (70% progress)
        await self.update_progress(job_id, 70, "Generating content")
        content = await self.generate_adapted_content(
            report_data, 
            request.template,
            request.audience,
            request.llm_config
        )
        
        # Step 4: Formatting (90% progress)
        await self.update_progress(job_id, 90, "Formatting report")
        formatted_report = await self.format_report(content, request.template)
        
        # Step 5: Complete (100% progress)
        await self.complete_job(job_id, formatted_report)
        return job_id
\`\`\`

### 2. Data Aggregation Logic

\`\`\`python
class SecurityDataAggregator:
    async def gather_security_data(self, time_range: TimeRange) -> ReportData:
        """
        Collect and aggregate security data from various sources
        """
        # Parallel data collection
        vulnerabilities = await self.get_vulnerabilities(time_range)
        scan_results = await self.get_scan_results(time_range)
        compliance_status = await self.get_compliance_status(time_range)
        metrics = await self.calculate_metrics(time_range)
        
        return ReportData(
            vulnerabilities=vulnerabilities,
            scan_results=scan_results,
            compliance_status=compliance_status,
            metrics=metrics
        )
    
    async def get_vulnerabilities(self, time_range: TimeRange) -> List[Vulnerability]:
        """Fetch from vulnerability scanners (OpenVAS, Nessus, etc.)"""
        pass
        
    async def get_scan_results(self, time_range: TimeRange) -> List[ScanResult]:
        """Fetch from various security tools (Nmap, ZAP, etc.)"""
        pass
\`\`\`

### 3. LLM Integration Logic

\`\`\`python
class LLMService:
    async def generate_adapted_content(
        self, 
        data: ReportData, 
        template: ReportTemplate,
        audience: AudienceProfile,
        config: LLMConfig
    ) -> str:
        """
        Generate report content adapted to audience
        """
        system_prompt = self.build_system_prompt(template, audience)
        user_prompt = self.build_data_prompt(data)
        
        if config.provider == "openai":
            return await self.openai_generate(system_prompt, user_prompt, config)
        elif config.provider == "perplexity":
            return await self.perplexity_generate(system_prompt, user_prompt, config)
    
    def build_system_prompt(self, template: ReportTemplate, audience: AudienceProfile) -> str:
        """Build context-aware system prompt"""
        return f"""
        Generate a {template.format} security report for {audience.name}.
        Technical level: {audience.technical_level}
        Focus areas: {', '.join(audience.focus_areas)}
        Required sections: {', '.join(template.sections)}
        """
\`\`\`

### 4. Research Integration

\`\`\`python
class ResearchService:
    async def conduct_research(self, query: str) -> ResearchData:
        """
        Conduct online security research using multiple sources
        """
        # Perplexity API for current threat intelligence
        perplexity_results = await self.perplexity_search(query)
        
        # CVE database lookup
        cve_results = await self.search_cve_database(query)
        
        # MITRE ATT&CK framework mapping
        mitre_results = await self.search_mitre_attack(query)
        
        return ResearchData(
            perplexity=perplexity_results,
            cve=cve_results,
            mitre=mitre_results
        )
\`\`\`

## Database Schema

### Reports Table
\`\`\`sql
CREATE TABLE reports (
    id UUID PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    template_id VARCHAR(100) NOT NULL,
    audience_id VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    metadata JSONB,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    created_by UUID REFERENCES users(id)
);
\`\`\`

### Report Jobs Table
\`\`\`sql
CREATE TABLE report_jobs (
    id UUID PRIMARY KEY,
    report_id UUID REFERENCES reports(id),
    status VARCHAR(50) NOT NULL,
    progress INTEGER DEFAULT 0,
    current_step VARCHAR(255),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
\`\`\`

## Security Considerations

### 1. API Key Management
- Store LLM API keys encrypted in database
- Use environment variables for service API keys
- Implement key rotation mechanism

### 2. Data Privacy
- Sanitize sensitive data before sending to external LLMs
- Implement data retention policies for generated reports
- Audit trail for report access and generation

### 3. Rate Limiting
- Implement rate limits on report generation endpoints
- Queue system for handling multiple concurrent requests
- Cost monitoring for LLM API usage

## Implementation Checklist

### Phase 1: Core Infrastructure
- [ ] Database schema setup
- [ ] Basic CRUD APIs for templates and audiences
- [ ] Job queue system (Redis/Celery)
- [ ] Progress tracking mechanism

### Phase 2: Data Integration
- [ ] Security data aggregation service
- [ ] Vulnerability scanner integrations
- [ ] Metrics calculation engine
- [ ] Data validation and sanitization

### Phase 3: AI Integration  
- [ ] LLM service abstraction layer
- [ ] OpenAI API integration
- [ ] Perplexity API integration
- [ ] Prompt engineering and optimization

### Phase 4: Research Features
- [ ] Online research service
- [ ] CVE database integration
- [ ] MITRE ATT&CK integration
- [ ] Research result caching

### Phase 5: Advanced Features
- [ ] Report scheduling and automation
- [ ] Email delivery system
- [ ] PDF generation service
- [ ] Report analytics and insights

## Error Handling Patterns

\`\`\`python
class ReportGenerationError(Exception):
    """Base exception for report generation errors"""
    pass

class DataCollectionError(ReportGenerationError):
    """Error during security data collection"""
    pass

class LLMGenerationError(ReportGenerationError):
    """Error during LLM content generation"""
    pass

# Error handling in service
try:
    report_data = await self.gather_security_data(time_range)
except DataCollectionError as e:
    await self.fail_job(job_id, f"Data collection failed: {str(e)}")
    raise
\`\`\`

## Monitoring and Observability

### Key Metrics to Track
- Report generation success/failure rates
- Average generation time per report type
- LLM API usage and costs
- Data source availability and response times
- User engagement with generated reports

### Logging Strategy
- Structured logging with correlation IDs
- Performance metrics at each pipeline stage
- Error details with context for debugging
- Audit logs for compliance tracking

## Testing Strategy

### Unit Tests
- Individual service method testing
- Mock external API dependencies
- Data aggregation logic validation

### Integration Tests  
- End-to-end report generation flow
- External API integration testing
- Database transaction testing

### Performance Tests
- Load testing for concurrent report generation
- LLM API response time benchmarking
- Data aggregation performance under scale

This documentation provides the foundation for implementing a robust, scalable reporting system backend that can handle complex security report generation with AI assistance.`,
          prerequisites: [
            'Advanced Python/FastAPI knowledge',
            'Database design experience',
            'API design principles',
            'AI/LLM integration experience',
            'Security domain knowledge'
          ],
          expectedOutcomes: [
            'Understand complete reporting system architecture',
            'Implement scalable backend services',
            'Integrate with multiple LLM providers',
            'Build secure and performant APIs',
            'Deploy production-ready reporting system'
          ],
          tags: ['backend', 'api', 'llm', 'reporting', 'architecture']
        }
      ]
    },
    {
      id: 'security-operations',
      title: 'Security Operations',
      description: 'Production security workflows and automation',
      icon: Shield,
      badge: 'Production',
      items: [
        {
          id: 'ticketing-attack-plans',
          title: 'Ticketing System & Attack Plans',
          description: 'Complete guide to automated security operations, ticketing integration, and continuous vulnerability management',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '45 minutes',
          content: `# Ticketing System & Attack Plans Guide

## Overview

The Production Security Center implements a continuous **Find-Fix-Verify** security operations model through automated attack plans and integrated ticketing systems. This creates a seamless workflow where security vulnerabilities are automatically discovered, tracked, remediated, and verified.

## Attack Plans Architecture

### What Are Attack Plans?

Attack Plans are **automated, scheduled security assessments** that continuously monitor your infrastructure for vulnerabilities. Think of them as your security team's automated assistants that never sleep.

### Core Components

#### 1. **Automated Scanning Engine**
\`\`\`typescript
interface AttackPlan {
  id: string;
  name: string;                    // e.g., "Daily Web App Scan"
  description: string;             // What this plan does  
  schedule: 'daily' | 'weekly' | 'monthly' | 'custom';
  enabled: boolean;                // Can be toggled on/off
  status: 'idle' | 'running' | 'completed' | 'failed';
  categories: string[];            // e.g., ['web-application', 'owasp-top10']
  targets: string[];               // e.g., ['app.company.com', 'api.company.com']
  lastRun?: Date;
  nextRun?: Date;
}
\`\`\`

#### 2. **Pre-configured Attack Categories**
- **Web Application Security**: OWASP Top 10, SQL injection, XSS, authentication bypass
- **API Security**: REST/GraphQL testing, authentication flaws, business logic errors
- **Infrastructure Security**: Network scanning, port enumeration, service discovery
- **Cloud Security**: AWS/Azure/GCP misconfigurations, IAM assessment, container security

#### 3. **Scheduling System**
- **Daily**: Critical assets scanned every 24 hours
- **Weekly**: Comprehensive infrastructure audits
- **Monthly**: Deep-dive assessments and compliance checks
- **Custom**: User-defined intervals and time windows

## Ticketing System Integration

### Automated Vulnerability-to-Ticket Pipeline

When an attack plan discovers a vulnerability, the system automatically:

1. **Analyzes** the finding (severity, impact, exploitability)
2. **Creates** a structured ticket in your chosen system
3. **Assigns** based on predefined rules
4. **Tracks** remediation progress
5. **Verifies** fixes through re-testing

### Supported Ticketing Systems

#### Jira Integration
\`\`\`json
{
  "provider": "jira",
  "apiUrl": "https://company.atlassian.net",
  "credentials": {
    "username": "security@company.com",
    "token": "ATATT3xFfGF0..."
  },
  "projectKey": "SEC",
  "issueType": "Security Bug",
  "priority": "High"
}
\`\`\`

#### ServiceNow Integration  
\`\`\`json
{
  "provider": "servicenow",
  "apiUrl": "https://company.service-now.com",
  "credentials": {
    "username": "api_user",
    "token": "abc123..."
  },
  "table": "incident",
  "category": "Security",
  "priority": "1 - Critical"
}
\`\`\`

#### Custom API Integration
\`\`\`json
{
  "provider": "custom",
  "apiUrl": "https://your-ticketing-api.com/tickets",
  "headers": {
    "Authorization": "Bearer token",
    "Content-Type": "application/json"
  },
  "mapping": {
    "title": "vulnerability.title",
    "description": "vulnerability.description",
    "severity": "vulnerability.cvss_score"
  }
}
\`\`\`

## Ticket Structure & Format

### Standard Ticket Fields

Every automatically generated ticket contains:

\`\`\`typescript
interface SecurityTicket {
  // Identification
  ticketId: string;                // "SEC-123"
  vulnerabilityId: string;         // "CVE-2024-0001" or internal ID
  
  // Content
  title: string;                   // "SQL Injection in Login Form"
  description: string;             // Detailed vulnerability information
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  
  // Classification
  category: string;                // "Web Application", "Network", etc.
  cweId?: string;                  // CWE-89 (SQL Injection)
  cvssScore?: number;              // 9.1
  
  // Location
  affectedAssets: string[];        // ["app.company.com", "api.company.com"]
  url?: string;                    // Specific endpoint if applicable
  
  // Remediation
  recommendedActions: string[];    // Step-by-step fix instructions
  references: string[];            // Links to documentation, patches
  
  // Workflow
  assignedTo: string;              // Team or individual
  priority: string;                // Based on business impact
  labels: string[];                // For categorization and filtering
}
\`\`\`

### Example Generated Ticket

\`\`\`markdown
**Title**: Critical SQL Injection Vulnerability in User Authentication

**Description**: 
A SQL injection vulnerability was discovered in the user login endpoint that allows attackers to bypass authentication and potentially access sensitive user data.

**Technical Details**:
- **Endpoint**: https://app.company.com/api/login
- **Parameter**: username (POST body)
- **Attack Vector**: \`admin' OR '1'='1' --\`
- **CVSS Score**: 9.1 (Critical)
- **CWE**: CWE-89 (SQL Injection)

**Impact**:
- Authentication bypass
- Potential data exfiltration
- Database manipulation possible

**Remediation Steps**:
1. Implement parameterized queries/prepared statements
2. Add input validation and sanitization
3. Apply principle of least privilege to database user
4. Enable SQL query logging for monitoring

**References**:
- OWASP SQL Injection Prevention: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
- Fix Examples: [Internal KB Link]

**Verification**:
- [ ] Code review completed
- [ ] Automated retest passed
- [ ] Penetration test verification
\`\`\`

## Remediation Tracking Workflow

### Lifecycle States

\`\`\`typescript
interface RemediationTracking {
  ticketId: string;
  vulnerabilityId: string;
  status: 'open' | 'in_progress' | 'resolved' | 'verified' | 'reopened';
  assignedTo: string;
  createdAt: Date;
  updatedAt: Date;
  verificationAttempts: number;
  autoRetest: boolean;
  retestSchedule?: Date;
}
\`\`\`

### State Transitions

1. **Open**: Vulnerability discovered, ticket created
2. **In Progress**: Developer/team assigned and working on fix
3. **Resolved**: Fix implemented, ready for verification
4. **Verified**: Automated retest confirms vulnerability is fixed
5. **Reopened**: Retest failed, vulnerability still present

## Configuration Best Practices

### Attack Plan Strategy

#### High-Value Targets (Daily Scans)
\`\`\`javascript
const criticalAssets = [
  'app.company.com',      // Customer-facing application
  'api.company.com',      // Public API endpoints  
  'admin.company.com',    // Administrative interfaces
  'payment.company.com'   // Payment processing
];
\`\`\`

#### Infrastructure Assessment (Weekly)
\`\`\`javascript
const infrastructureTargets = [
  '10.0.0.0/24',         // Internal network ranges
  'vpn.company.com',     // VPN endpoints
  'mail.company.com',    // Email infrastructure
  'dns1.company.com'     // DNS servers
];
\`\`\`

### Ticketing Configuration

#### Auto-Assignment Rules
\`\`\`json
{
  "assignment_rules": [
    {
      "condition": "category == 'Web Application'",
      "assignee": "web-dev-team",
      "cc": ["security-team"]
    },
    {
      "condition": "severity == 'Critical'",
      "assignee": "security-incident-team",
      "priority": "Immediate"
    },
    {
      "condition": "cvss_score >= 7.0",
      "assignee": "senior-developer",
      "labels": ["high-risk", "security"]
    }
  ]
}
\`\`\`

## Metrics and Reporting

### Key Performance Indicators

#### Discovery Metrics
- Vulnerabilities found per scan
- False positive rate
- Coverage metrics (assets scanned vs. total assets)
- Time to discovery (0-day to detection)

#### Response Metrics  
- Mean Time to Acknowledge (MTTA)
- Mean Time to Resolve (MTTR)
- Fix rate percentage
- SLA compliance rate

#### Quality Metrics
- Vulnerability recurrence rate
- Verification success rate
- Escalation frequency
- Team response effectiveness

## Security Considerations

### Data Protection
- **Encryption**: All ticket data encrypted in transit and at rest
- **Access Control**: Role-based access to vulnerability details
- **Audit Logging**: Complete trail of all ticket modifications
- **Data Retention**: Configurable retention policies for compliance

### API Security
- **Authentication**: API tokens with limited scope and expiration
- **Rate Limiting**: Prevent abuse of ticketing APIs
- **IP Whitelisting**: Restrict API access to authorized networks
- **Webhook Verification**: Validate incoming webhook signatures

This system creates a robust, automated security operations pipeline that scales with your organization while maintaining the human oversight needed for effective security management.`,
          prerequisites: [
            'Basic understanding of security operations',
            'Familiarity with ticketing systems (Jira/ServiceNow)',
            'Knowledge of vulnerability management',
            'Understanding of DevSecOps workflows'
          ],
          expectedOutcomes: [
            'Configure automated attack plans effectively',
            'Set up ticketing system integrations',
            'Understand remediation tracking workflows',
            'Implement continuous security operations',
            'Monitor and optimize security processes'
          ],
          tags: ['security-operations', 'ticketing', 'attack-plans', 'automation', 'remediation']
        }
      ]
    },
    {
      id: 'siem-monitoring',
      title: 'SIEM Monitoring',
      description: 'Wazuh SIEM management and log analysis',
      icon: Eye,
      badge: 'Real-time',
      items: [
        {
          id: 'wazuh-siem-management',
          title: 'Wazuh SIEM Management Guide',
          description: 'Complete guide to Wazuh SIEM deployment, log sources, endpoint monitoring, and threat detection',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '60 minutes',
          content: `# Wazuh SIEM Management Guide

## Overview

Wazuh SIEM (Security Information and Event Management) is the centralized security monitoring and incident detection engine of the IPS Security Center. It provides real-time log analysis, threat detection, compliance monitoring, and security incident response capabilities across your entire infrastructure.

## What is Wazuh SIEM?

Wazuh is an open-source security platform that unifies XDR (Extended Detection and Response) and SIEM capabilities. In the context of the IPS Security Center, it serves as:

- **Central Log Aggregator**: Collects security events from all systems
- **Threat Detection Engine**: Analyzes patterns to identify security incidents  
- **Compliance Monitor**: Ensures adherence to security standards
- **Incident Response Hub**: Orchestrates response to security events
- **Forensic Analysis Tool**: Provides detailed investigation capabilities

## Architecture Overview

### Core Components

\`\`\`typescript
interface WazuhArchitecture {
  manager: {
    role: 'Central coordination and analysis';
    components: ['Rule Engine', 'Event Correlation', 'Alert Management'];
    port: 1514; // Agent communication
    api_port: 55000; // REST API
  };
  agents: {
    role: 'Data collection from endpoints';
    types: ['File Integrity', 'Log Collection', 'Rootkit Detection'];
    communication: 'Encrypted (AES + Blowfish)';
  };
  indexer: {
    role: 'Data storage and search';
    technology: 'OpenSearch/Elasticsearch';
    port: 9200;
  };
  dashboard: {
    role: 'Visualization and management';
    technology: 'OpenSearch Dashboards';
    port: 443;
  };
}
\`\`\`

### Data Flow Pipeline

\`\`\`
Log Sources → Wazuh Agents → Wazuh Manager → Rules Engine → Alerts → Dashboard/API
     ↓              ↓              ↓             ↓          ↓         ↓
  Endpoints    Collection     Normalization  Analysis  Notification  Action
\`\`\`

## Data Sources and Endpoints

### 1. **System Infrastructure Logs**

#### Linux/Unix Systems
\`\`\`bash
# System logs
/var/log/syslog          # System events
/var/log/auth.log        # Authentication events  
/var/log/secure          # SSH, sudo, su events
/var/log/messages        # General system messages
/var/log/dmesg           # Kernel messages

# Service-specific logs
/var/log/apache2/        # Web server logs
/var/log/nginx/          # Reverse proxy logs
/var/log/mysql/          # Database logs
/var/log/postgresql/     # PostgreSQL logs
\`\`\`

#### Windows Systems
\`\`\`powershell
# Event logs
Security                 # Authentication, privileges
System                   # System components, drivers
Application              # Applications, services
Setup                    # System setup, updates

# IIS logs (if applicable)
C:\\inetpub\\logs\\LogFiles\\

# Custom application logs
%ProgramData%\\ApplicationName\\Logs\\
\`\`\`

#### Network Infrastructure
\`\`\`yaml
# Firewall logs
iptables_logs: /var/log/iptables.log
pf_logs: /var/log/pflog
cisco_asa: syslog_endpoint:514

# Network device logs  
switches: 
  - device: "10.0.1.1"
    type: "cisco_ios"
    syslog_facility: "local0"
    
routers:
  - device: "10.0.1.254" 
    type: "juniper"
    syslog_facility: "local1"
\`\`\`

### 2. **Application Security Logs**

#### Web Application Logs
\`\`\`json
{
  "apache_access": {
    "path": "/var/log/apache2/access.log",
    "format": "combined",
    "events": ["HTTP requests", "Response codes", "User agents"]
  },
  "apache_error": {
    "path": "/var/log/apache2/error.log", 
    "events": ["Application errors", "Security warnings", "Module failures"]
  },
  "nginx_access": {
    "path": "/var/log/nginx/access.log",
    "format": "json",
    "events": ["Request details", "Response times", "Client IPs"]
  }
}
\`\`\`

#### Database Security Events
\`\`\`sql
-- MySQL/MariaDB
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';
SET GLOBAL slow_query_log = 'ON';

-- PostgreSQL
log_statement = 'all'
log_connections = on
log_disconnections = on
log_checkpoints = on
\`\`\`

### 3. **Cloud Infrastructure Logs**

#### AWS CloudTrail Integration
\`\`\`json
{
  "aws_cloudtrail": {
    "s3_bucket": "company-cloudtrail-logs",
    "regions": ["us-east-1", "us-west-2"],
    "events": ["API calls", "Console sign-ins", "Resource modifications", "IAM changes"],
    "integration_method": "S3 bucket monitoring"
  }
}
\`\`\`

### 4. **Container and Orchestration Logs**

#### Kubernetes Cluster Logs
\`\`\`yaml
kubernetes_logs:
  api_server: 
    path: "/var/log/kube-apiserver.log"
    events: ["API requests", "Authentication", "Authorization"]
    
  kubelet:
    path: "/var/log/kubelet.log"  
    events: ["Pod lifecycle", "Resource allocation", "Node status"]
    
  audit_logs:
    path: "/var/log/kubernetes/audit.log"
    events: ["Resource access", "Policy violations", "Admin actions"]
\`\`\`

## Log Processing and Analysis

### 1. **Custom Rule Development**

#### Security Event Rules
\`\`\`xml
<!-- SQL Injection Detection -->
<rule id="100001" level="12">
  <if_sid>31100</if_sid>
  <regex>union|select|insert|delete|update|drop|create|alter</regex>
  <description>Possible SQL injection attack</description>
  <group>web_attack,sql_injection</group>
</rule>

<!-- Brute Force Detection -->  
<rule id="100002" level="10" frequency="10" timeframe="60">
  <if_matched_sid>5716</if_matched_sid>
  <description>Multiple SSH authentication failures</description>
  <group>authentication_failures,brute_force</group>
</rule>
\`\`\`

## Integration Patterns

### 1. **REST API Integration**

\`\`\`python
import requests

class WazuhAPIClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.authenticate(username, password)
    
    def get_agents(self):
        """Get all registered agents"""
        response = self.session.get(f"{self.base_url}/agents")
        return response.json()["data"]["affected_items"]
    
    def get_alerts(self, limit: int = 500, severity: str = None):
        """Get security alerts"""
        params = {"limit": limit}
        if severity:
            params["q"] = f"rule.level>={severity}"
        
        response = self.session.get(f"{self.base_url}/alerts", params=params)
        return response.json()["data"]["affected_items"]
\`\`\`

### 2. **Real-time Event Processing**

\`\`\`python
def process_security_event(event):
    """Process incoming security events"""
    
    if event.get("rule", {}).get("level", 0) >= 10:
        # High severity - immediate action
        create_incident(event)
        notify_security_team(event)
    
    elif "authentication_failure" in event.get("rule", {}).get("groups", []):
        # Track failed logins
        track_failed_login(event)
    
    # Store for compliance and forensics
    store_event(event)
\`\`\`

## Alert Management and Response

### Alert Severity Classification

\`\`\`yaml
severity_levels:
  0-3:   # Informational
    priority: "Low"
    response_time: "24 hours"
    action: "Log for analysis"
    
  4-7:   # Warning  
    priority: "Medium"
    response_time: "4 hours"
    action: "Investigate and assess"
    
  8-11:  # Error
    priority: "High" 
    response_time: "1 hour"
    action: "Immediate investigation"
    
  12-15: # Critical
    priority: "Critical"
    response_time: "15 minutes"
    action: "Immediate response and containment"
\`\`\`

## Compliance and Reporting

### Compliance Framework Mapping

#### PCI DSS Requirements
\`\`\`yaml
pci_dss_mapping:
  requirement_10:  # Logging and monitoring
    rules: [5700, 5701, 5706, 5707]  # Authentication events
    description: "Track and monitor all access to network resources"
    
  requirement_11:  # Security testing
    rules: [100001, 100020, 100021]  # Attack detection
    description: "Regularly test security systems and processes"
\`\`\`

## Performance Optimization

### Log Processing Optimization

\`\`\`xml
<!-- Efficient rule structure -->
<rule id="100030" level="0">
  <if_sid>5716</if_sid>
  <regex>^Failed password for</regex>
  <description>SSH authentication failure (parent rule)</description>
</rule>

<rule id="100031" level="5">
  <if_sid>100030</if_sid>
  <regex>invalid user</regex>
  <description>SSH login attempt with invalid user</description>
  <group>authentication_failures</group>
</rule>
\`\`\`

## Key Benefits

### Real-time Threat Detection
- **Continuous Monitoring**: 24/7 analysis of security events
- **Pattern Recognition**: Advanced correlation to identify attack patterns
- **False Positive Reduction**: Machine learning-enhanced rule tuning
- **Automated Response**: Immediate containment of detected threats

### Comprehensive Coverage
- **Multi-platform Support**: Windows, Linux, macOS, mobile devices
- **Cloud Integration**: AWS, Azure, GCP native log ingestion
- **Container Monitoring**: Docker, Kubernetes, container orchestration
- **Network Visibility**: Firewall, router, switch, and IDS/IPS integration

### Compliance Assurance  
- **Regulatory Frameworks**: PCI DSS, HIPAA, SOC 2, ISO 27001
- **Automated Reporting**: Scheduled compliance reports and dashboards
- **Audit Trail**: Complete forensic investigation capabilities
- **Data Retention**: Configurable retention policies for compliance requirements

This comprehensive SIEM deployment provides the visibility and control needed to maintain a strong security posture across your entire infrastructure.`,
          prerequisites: [
            'Advanced Linux/Windows administration',
            'Network security fundamentals',
            'Log analysis experience',
            'Security operations knowledge',
            'API integration experience'
          ],
          expectedOutcomes: [
            'Deploy and configure Wazuh SIEM effectively',
            'Integrate multiple log sources and endpoints',
            'Create custom detection rules and alerts',
            'Implement automated incident response',
            'Maintain compliance with security frameworks',
            'Optimize SIEM performance and storage'
          ],
          tags: ['siem', 'wazuh', 'log-analysis', 'threat-detection', 'compliance', 'monitoring']
        }
      ]
    }
  ];

  // Helper functions
  const handleSearch = (query: string) => {
    setSearchQuery(query);
    if (query) {
      // Auto-expand sections with matching content
      const matchingSections = documentationSections
        .filter(section => 
          section.title.toLowerCase().includes(query.toLowerCase()) ||
          section.description.toLowerCase().includes(query.toLowerCase()) ||
          section.items.some(item => 
            item.title.toLowerCase().includes(query.toLowerCase()) ||
            item.description.toLowerCase().includes(query.toLowerCase()) ||
            item.content.toLowerCase().includes(query.toLowerCase())
          )
        )
        .map(section => section.id);
      
      setExpandedSections(prev => [...new Set([...prev, ...matchingSections])]);
    }
  };

  const toggleSection = (sectionId: string) => {
    setExpandedSections(prev => 
      prev.includes(sectionId) 
        ? prev.filter(id => id !== sectionId)
        : [...prev, sectionId]
    );
  };

  const toggleBookmark = (docId: string) => {
    setBookmarkedDocs(prev => 
      prev.includes(docId) 
        ? prev.filter(id => id !== docId)
        : [...prev, docId]
    );
    toast({
      title: bookmarkedDocs.includes(docId) ? "Bookmark Removed" : "Bookmark Added",
      description: "Documentation bookmark updated"
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Content has been copied successfully"
    });
  };

  // Filter and search logic
  const getFilteredItems = (items: DocItem[]) => {
    return items.filter(item => {
      const matchesSearch = !searchQuery || 
        item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.content.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesType = filterType === 'all' || item.type === filterType;
      const matchesDifficulty = filterDifficulty === 'all' || item.difficulty === filterDifficulty;
      
      return matchesSearch && matchesType && matchesDifficulty;
    });
  };

  const selectedDocItem = selectedDoc 
    ? documentationSections.flatMap(s => s.items).find(item => item.id === selectedDoc)
    : null;

  const getBreadcrumbs = () => {
    if (!selectedDoc) return [];
    
    const section = documentationSections.find(s => 
      s.items.some(item => item.id === selectedDoc)
    );
    
    return section ? [section.title, selectedDocItem?.title] : [];
  };

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-6xl max-h-[85vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            Documentation Library
            {selectedDoc && (
              <div className="flex items-center text-sm text-muted-foreground ml-4">
                <Home className="h-4 w-4" />
                {getBreadcrumbs().map((crumb, index) => (
                  <React.Fragment key={index}>
                    <ChevronRight className="h-3 w-3 mx-1" />
                    <span>{crumb}</span>
                  </React.Fragment>
                ))}
              </div>
            )}
          </DialogTitle>
        </DialogHeader>

        <div className="flex h-[calc(85vh-6rem)] gap-4">
          {/* Compact Sidebar */}
          <div className="w-72 border-r pr-4 space-y-4">
            {/* Search & Filters */}
            <div className="space-y-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search docs..."
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-10 h-8"
                />
              </div>
              
              <div className="flex gap-2">
                <select 
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="flex h-7 rounded-md border border-input bg-background px-2 py-1 text-xs"
                >
                  <option value="all">All Types</option>
                  <option value="guide">Guides</option>
                  <option value="tutorial">Tutorials</option>
                  <option value="reference">Reference</option>
                </select>
                
                <select 
                  value={filterDifficulty}
                  onChange={(e) => setFilterDifficulty(e.target.value)}
                  className="flex h-7 rounded-md border border-input bg-background px-2 py-1 text-xs"
                >
                  <option value="all">All Levels</option>
                  <option value="beginner">Beginner</option>
                  <option value="intermediate">Intermediate</option>
                  <option value="advanced">Advanced</option>
                </select>
              </div>
            </div>

            {/* Navigation Tree */}
            <ScrollArea className="h-full">
              <div className="space-y-1">
                {documentationSections.map((section) => {
                  const filteredItems = getFilteredItems(section.items);
                  if (filteredItems.length === 0 && searchQuery) return null;
                  
                  return (
                    <Collapsible
                      key={section.id}
                      open={expandedSections.includes(section.id)}
                      onOpenChange={() => toggleSection(section.id)}
                    >
                      <CollapsibleTrigger asChild>
                        <Button
                          variant="ghost"
                          className="w-full justify-between p-2 h-auto text-left hover:bg-muted/50"
                        >
                          <div className="flex items-center gap-2">
                            <section.icon className="h-4 w-4" />
                            <div className="flex-1">
                              <div className="font-medium text-sm">{section.title}</div>
                              <div className="text-xs text-muted-foreground">
                                {filteredItems.length} items
                              </div>
                            </div>
                            {section.badge && (
                              <Badge variant="secondary" className="text-xs">
                                {section.badge}
                              </Badge>
                            )}
                          </div>
                          {expandedSections.includes(section.id) ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </Button>
                      </CollapsibleTrigger>
                      
                      <CollapsibleContent className="space-y-1 ml-6">
                        {filteredItems.map((item) => (
                          <Button
                            key={item.id}
                            variant={selectedDoc === item.id ? "secondary" : "ghost"}
                            className="w-full justify-start p-2 h-auto text-left"
                            onClick={() => setSelectedDoc(item.id)}
                          >
                            <div className="flex items-center gap-2 w-full">
                              <FileText className="h-3 w-3" />
                              <div className="flex-1 min-w-0">
                                <div className="font-medium text-xs truncate">{item.title}</div>
                                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                  <Badge variant="outline" className="text-xs px-1 py-0">
                                    {item.type}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs px-1 py-0">
                                    {item.difficulty}
                                  </Badge>
                                </div>
                              </div>
                              {bookmarkedDocs.includes(item.id) && (
                                <BookmarkCheck className="h-3 w-3 text-primary" />
                              )}
                            </div>
                          </Button>
                        ))}
                      </CollapsibleContent>
                    </Collapsible>
                  );
                })}
              </div>
            </ScrollArea>
          </div>

          {/* Main Content Area */}
          <div className="flex-1 min-w-0">
            {selectedDoc && selectedDocItem ? (
              /* Document View */
              <div className="h-full flex flex-col">
                {/* Document Header */}
                <div className="flex items-center justify-between mb-4 pb-2 border-b">
                  <div className="flex items-center gap-2 min-w-0">
                    <Button 
                      variant="ghost" 
                      size="sm"
                      onClick={() => setSelectedDoc(null)}
                    >
                      ← Back
                    </Button>
                    <div className="min-w-0">
                      <h2 className="font-semibold text-lg truncate">{selectedDocItem.title}</h2>
                      <p className="text-sm text-muted-foreground">{selectedDocItem.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleBookmark(selectedDoc)}
                    >
                      {bookmarkedDocs.includes(selectedDoc) ? (
                        <BookmarkCheck className="h-4 w-4" />
                      ) : (
                        <Bookmark className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(selectedDocItem.content)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Document Content Tabs */}
                <div className="flex-1 overflow-hidden">
                  <Tabs defaultValue="content" className="h-full flex flex-col">
                    <TabsList className="grid w-full grid-cols-3">
                      <TabsTrigger value="content">Content</TabsTrigger>
                      <TabsTrigger value="info">Details</TabsTrigger>
                      <TabsTrigger value="qa">QA</TabsTrigger>
                    </TabsList>

                    <TabsContent value="content" className="flex-1 mt-4 overflow-hidden">
                      <ScrollArea className="h-full">
                        <div className="prose prose-sm max-w-none">
                          <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">
                            {selectedDocItem.content}
                          </pre>
                        </div>
                      </ScrollArea>
                    </TabsContent>

                    <TabsContent value="info" className="mt-4">
                      <div className="grid grid-cols-2 gap-4">
                        <Card>
                          <CardHeader>
                            <CardTitle className="text-base">Document Info</CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span>Type:</span>
                              <Badge variant="outline">{selectedDocItem.type}</Badge>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span>Difficulty:</span>
                              <Badge variant="outline">{selectedDocItem.difficulty}</Badge>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span>Est. Time:</span>
                              <span>{selectedDocItem.estimatedTime}</span>
                            </div>
                          </CardContent>
                        </Card>

                        {selectedDocItem.prerequisites && (
                          <Card>
                            <CardHeader>
                              <CardTitle className="text-base">Prerequisites</CardTitle>
                            </CardHeader>
                            <CardContent>
                              <ul className="text-sm space-y-1">
                                {selectedDocItem.prerequisites.map((prereq, index) => (
                                  <li key={index} className="flex items-start gap-2">
                                    <CheckCircle className="h-3 w-3 text-green-500 mt-0.5" />
                                    {prereq}
                                  </li>
                                ))}
                              </ul>
                            </CardContent>
                          </Card>
                        )}
                      </div>

                      {selectedDocItem.expectedOutcomes && (
                        <Card className="mt-4">
                          <CardHeader>
                            <CardTitle className="text-base">Expected Outcomes</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ul className="text-sm space-y-1">
                              {selectedDocItem.expectedOutcomes.map((outcome, index) => (
                                <li key={index} className="flex items-start gap-2">
                                  <Star className="h-3 w-3 text-yellow-500 mt-0.5" />
                                  {outcome}
                                </li>
                              ))}
                            </ul>
                          </CardContent>
                        </Card>
                      )}
                    </TabsContent>

                    <TabsContent value="qa" className="mt-4">
                      {selectedDocItem.qaSteps ? (
                        <div className="space-y-4">
                          {selectedDocItem.qaSteps.map((step, index) => (
                            <Card key={index}>
                              <CardHeader>
                                <CardTitle className="text-sm">Step {index + 1}: {step.step}</CardTitle>
                              </CardHeader>
                              <CardContent className="space-y-2">
                                <div>
                                  <span className="text-sm font-medium">Expected Result:</span>
                                  <p className="text-sm text-muted-foreground">{step.expectedResult}</p>
                                </div>
                                {step.troubleshooting && (
                                  <div>
                                    <span className="text-sm font-medium">Troubleshooting:</span>
                                    <p className="text-sm text-muted-foreground">{step.troubleshooting}</p>
                                  </div>
                                )}
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      ) : (
                        <Card>
                          <CardContent className="pt-6">
                            <p className="text-muted-foreground text-center">No QA steps defined for this document.</p>
                          </CardContent>
                        </Card>
                      )}
                    </TabsContent>
                  </Tabs>
                </div>
              </div>
            ) : (
              /* Overview/Home View */
              <div className="h-full">
                <div className="mb-6">
                  <h2 className="text-2xl font-bold mb-2">Documentation Overview</h2>
                  <p className="text-muted-foreground">
                    Comprehensive guides, tutorials, and references for the IPS Security Center
                  </p>
                </div>

                <ScrollArea className="h-full">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {documentationSections.map((section) => {
                      const filteredItems = getFilteredItems(section.items);
                      if (filteredItems.length === 0 && searchQuery) return null;
                      
                      return (
                        <Card 
                          key={section.id} 
                          className="cursor-pointer hover:bg-muted/50 transition-colors"
                          onClick={() => {
                            setSelectedSection(section.id);
                            if (!expandedSections.includes(section.id)) {
                              toggleSection(section.id);
                            }
                          }}
                        >
                          <CardHeader>
                            <div className="flex items-center gap-3">
                              <section.icon className="h-6 w-6" />
                              <div className="flex-1">
                                <CardTitle className="flex items-center gap-2">
                                  {section.title}
                                  {section.badge && (
                                    <Badge variant="secondary" className="text-xs">
                                      {section.badge}
                                    </Badge>
                                  )}
                                </CardTitle>
                                <CardDescription>{section.description}</CardDescription>
                              </div>
                            </div>
                          </CardHeader>
                          <CardContent>
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-muted-foreground">
                                {filteredItems.length} item{filteredItems.length !== 1 ? 's' : ''}
                              </span>
                              <ChevronRight className="h-4 w-4" />
                            </div>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                </ScrollArea>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};