# 🏠 Local Model Deployment Guide for Penetration Testing

## Table of Contents
1. [Overview](#overview)
2. [Ollama Deployment](#ollama-deployment)
3. [LM Studio Setup](#lm-studio-setup)
4. [Text Generation WebUI](#text-generation-webui)
5. [Hardware Requirements](#hardware-requirements)
6. [Security-Focused Model Selection](#security-focused-model-selection)
7. [Performance Optimization](#performance-optimization)
8. [Integration Examples](#integration-examples)
9. [Troubleshooting](#troubleshooting)

## Overview

Local model deployment provides complete privacy, control, and independence from cloud services for penetration testing operations. This guide covers comprehensive setup, optimization, and integration procedures.

### Benefits of Local Deployment
- **Complete Privacy**: No data sent to external services
- **Offline Operation**: Works without internet connectivity
- **Cost Control**: No per-token usage fees
- **Customization**: Full control over model behavior
- **Compliance**: Meets strict data governance requirements
- **Performance**: Dedicated hardware resources

### Architecture Overview
```
┌─────────────────────────────────────────────────────────┐
│                Pentest Interface                        │
├─────────────────────────────────────────────────────────┤
│                AI Agent Manager                         │
├─────────────────────────────────────────────────────────┤
│     Local Model API (Ollama/LM Studio/WebUI)          │
├─────────────────────────────────────────────────────────┤
│              Local AI Model                            │
│        (Llama 2, Mistral, CodeLlama, etc.)            │
├─────────────────────────────────────────────────────────┤
│              Hardware Layer                            │
│           (CPU, GPU, RAM, Storage)                     │
└─────────────────────────────────────────────────────────┘
```

## Ollama Deployment

### Installation

#### Linux/macOS Installation
```bash
# Download and install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Verify installation
ollama --version

# Start Ollama service
ollama serve
```

#### Windows Installation
```powershell
# Download from https://ollama.com/download
# Run the installer
# Verify installation
ollama --version
```

#### Docker Deployment
```bash
# Pull Ollama Docker image
docker pull ollama/ollama

# Run Ollama container
docker run -d \
  --name ollama \
  -p 11434:11434 \
  -v ollama:/root/.ollama \
  ollama/ollama

# Run with GPU support (NVIDIA)
docker run -d \
  --gpus all \
  --name ollama-gpu \
  -p 11434:11434 \
  -v ollama:/root/.ollama \
  ollama/ollama
```

### Model Installation and Management

#### Security-Focused Models

**1. Llama 2 13B (Recommended for General Security)**
```bash
# Download and install
ollama pull llama2:13b

# Test the model
ollama run llama2:13b "Explain SQL injection vulnerabilities"
```

**Expected Performance**:
```yaml
Model: llama2:13b
Memory Usage: ~8-10GB RAM
Response Time: 5-15 seconds
Strengths:
  - Good general security knowledge
  - Reasonable inference speed
  - Well-documented vulnerabilities understanding
  - Ethical reasoning capabilities
Best For:
  - General vulnerability analysis
  - Security report generation
  - Risk assessment narratives
  - Basic penetration testing guidance
```

**2. Code Llama 34B (Code Security Analysis)**
```bash
# Download (requires significant resources)
ollama pull codellama:34b

# Test with code analysis
ollama run codellama:34b "Review this PHP code for security issues: <?php echo $_GET['user']; ?>"
```

**Expected Performance**:
```yaml
Model: codellama:34b
Memory Usage: ~20-24GB RAM
Response Time: 15-30 seconds
Strengths:
  - Excellent code vulnerability detection
  - Multiple programming language support
  - Detailed security code reviews
  - Secure coding recommendations
Best For:
  - Static code analysis
  - Secure code review
  - API security assessment
  - DevSecOps integration
```

**3. Mistral 7B (Fast Security Analysis)**
```bash
# Quick installation
ollama pull mistral:7b

# Test performance
ollama run mistral:7b "What are the OWASP Top 10 vulnerabilities?"
```

**Expected Performance**:
```yaml
Model: mistral:7b
Memory Usage: ~4-6GB RAM
Response Time: 2-8 seconds
Strengths:
  - Fast inference speed
  - Good general knowledge
  - Efficient resource usage
  - Multilingual capabilities
Best For:
  - Quick security assessments
  - Real-time analysis
  - Resource-constrained environments
  - Rapid prototyping
```

### Custom Model Configuration

#### Creating Custom Security Models
```bash
# Create a Modelfile for security-focused fine-tuning
cat > SecurityExpert.Modelfile << EOF
FROM llama2:13b

# Set security-focused system prompt
SYSTEM """
You are a cybersecurity expert specializing in penetration testing, vulnerability assessment, and security analysis. 

Key competencies:
- OWASP Top 10 vulnerabilities
- Network security assessment
- Web application security
- Risk assessment and CVSS scoring
- Compliance frameworks (NIST, ISO 27001)

Always provide:
- Detailed technical analysis
- Actionable remediation steps
- Risk prioritization
- Compliance mapping
- Ethical considerations

Maintain professional standards and focus on authorized security testing only.
"""

# Set temperature for consistent security analysis
PARAMETER temperature 0.2
PARAMETER top_k 10
PARAMETER top_p 0.9

# Set context window
PARAMETER num_ctx 4096
EOF

# Build the custom model
ollama create security-expert -f SecurityExpert.Modelfile

# Test the custom model
ollama run security-expert "Analyze the security risks of using default passwords"
```

#### Configuration Management
```bash
# List installed models
ollama list

# Show model information
ollama show llama2:13b

# Remove unused models
ollama rm mistral:7b

# Update models
ollama pull llama2:13b
```

### API Integration

#### Basic API Usage
```bash
# Test API endpoint
curl http://localhost:11434/api/version

# Generate response
curl http://localhost:11434/api/generate -d '{
  "model": "llama2:13b",
  "prompt": "Explain Cross-Site Scripting (XSS) vulnerabilities and prevention methods",
  "stream": false
}'
```

#### Advanced API Configuration
```javascript
// JavaScript integration example
const ollamaConfig = {
  baseURL: 'http://localhost:11434',
  model: 'security-expert',
  options: {
    temperature: 0.2,
    top_k: 10,
    top_p: 0.9,
    num_ctx: 4096
  }
};

async function analyzeVulnerability(description) {
  const response = await fetch(`${ollamaConfig.baseURL}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: ollamaConfig.model,
      prompt: `Analyze this security vulnerability: ${description}`,
      stream: false,
      options: ollamaConfig.options
    })
  });
  
  const result = await response.json();
  return result.response;
}
```

## LM Studio Setup

### Installation and Configuration

#### System Requirements
- **OS**: Windows 10/11, macOS 12+, or Linux
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 50GB+ free space
- **GPU**: NVIDIA RTX series recommended (optional)

#### Installation Process
1. Download LM Studio from [lmstudio.ai](https://lmstudio.ai)
2. Install and launch the application
3. Navigate to the "Models" tab
4. Search and download security-focused models

#### Recommended Models for Security

**1. TheBloke/Llama-2-13B-Chat-GGML**
```yaml
Model Name: TheBloke/Llama-2-13B-Chat-GGML
File Size: ~7.3GB (Q4_0 quantization)
Memory Usage: ~8GB RAM
Performance: Excellent for security analysis
Download Command: Search "TheBloke Llama-2-13B" in LM Studio
```

**2. TheBloke/CodeLlama-13B-Instruct-GGML**
```yaml
Model Name: TheBloke/CodeLlama-13B-Instruct-GGML
File Size: ~7.3GB (Q4_0 quantization)
Memory Usage: ~8GB RAM
Performance: Specialized for code security review
Download Command: Search "CodeLlama-13B-Instruct" in LM Studio
```

### API Server Configuration

#### Starting the Local Server
1. Open LM Studio
2. Navigate to "Local Server" tab
3. Select your downloaded model
4. Configure server settings:
   ```json
   {
     "port": 1234,
     "cors_enabled": true,
     "max_tokens": 2048,
     "temperature": 0.2,
     "top_p": 0.9
   }
   ```
5. Click "Start Server"

#### Testing the API
```bash
# Test server status
curl http://localhost:1234/v1/models

# Test completion
curl http://localhost:1234/v1/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "local-model",
    "prompt": "Explain buffer overflow vulnerabilities",
    "max_tokens": 500,
    "temperature": 0.2
  }'
```

### Performance Optimization

#### GPU Acceleration
```json
{
  "gpu_enabled": true,
  "gpu_layers": 35,
  "gpu_memory_utilization": 0.8,
  "batch_size": 512
}
```

#### CPU Optimization
```json
{
  "cpu_threads": 8,
  "cpu_batch_size": 256,
  "memory_map": true,
  "memory_lock": true
}
```

## Text Generation WebUI

### Installation

#### Using Conda (Recommended)
```bash
# Clone repository
git clone https://github.com/oobabooga/text-generation-webui.git
cd text-generation-webui

# Create conda environment
conda create -n textgen python=3.10
conda activate textgen

# Install dependencies
pip install -r requirements.txt

# Install additional dependencies for CUDA (if using GPU)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

#### Docker Deployment
```bash
# Clone and setup
git clone https://github.com/oobabooga/text-generation-webui.git
cd text-generation-webui

# Build Docker image
docker build -t textgen-webui .

# Run with GPU support
docker run -d \
  --gpus all \
  -p 7860:7860 \
  -p 5000:5000 \
  -v $(pwd)/models:/app/models \
  -v $(pwd)/characters:/app/characters \
  textgen-webui
```

### Model Management

#### Downloading Security Models
```bash
# Navigate to text-generation-webui directory
cd text-generation-webui

# Download models using the built-in script
python download-model.py --model TheBloke/Llama-2-13B-Chat-GGML

# Or download manually to models/ directory
wget -P models/ https://huggingface.co/TheBloke/Llama-2-13B-Chat-GGML/resolve/main/llama-2-13b-chat.q4_0.bin
```

### API Configuration

#### Starting the API Server
```bash
# Start with API enabled
python server.py --api --listen --listen-port 5000

# With custom model
python server.py --api --model llama-2-13b-chat --listen --listen-port 5000

# With GPU acceleration
python server.py --api --model llama-2-13b-chat --gpu-memory 8 --listen --listen-port 5000
```

#### API Usage Examples
```python
import requests
import json

# API configuration
API_BASE = "http://localhost:5000"

def generate_security_analysis(prompt):
    url = f"{API_BASE}/api/v1/generate"
    
    payload = {
        "prompt": prompt,
        "max_new_tokens": 500,
        "temperature": 0.2,
        "top_p": 0.9,
        "repetition_penalty": 1.1,
        "stop": ["\n\n"]
    }
    
    response = requests.post(url, json=payload)
    return response.json()["results"][0]["text"]

# Example usage
vulnerability_analysis = generate_security_analysis(
    "Analyze the security implications of SQL injection in web applications"
)
print(vulnerability_analysis)
```

## Hardware Requirements

### Minimum System Requirements

#### CPU-Only Deployment
```yaml
Processor: 
  - Intel i5-8400 or AMD Ryzen 5 2600
  - 6+ cores recommended
Memory:
  - 16GB RAM (minimum)
  - 32GB RAM (recommended)
Storage:
  - 100GB+ SSD storage
  - NVMe preferred for better performance
Network:
  - Gigabit Ethernet (for model downloads)
```

#### GPU-Accelerated Deployment
```yaml
GPU:
  - NVIDIA RTX 3080 (12GB VRAM) - Minimum
  - NVIDIA RTX 4090 (24GB VRAM) - Recommended
  - NVIDIA A6000/A100 - Enterprise
CPU:
  - Intel i7-9700K or AMD Ryzen 7 3700X
  - 8+ cores recommended
Memory:
  - 32GB RAM (minimum)
  - 64GB RAM (recommended for large models)
Storage:
  - 200GB+ NVMe SSD
Power:
  - 850W+ PSU for high-end GPUs
Cooling:
  - Adequate case ventilation
  - Consider liquid cooling for sustained workloads
```

### Performance Benchmarks

#### Model Size vs Hardware Requirements
| Model Size | RAM (CPU) | VRAM (GPU) | Inference Speed | Quality |
|------------|-----------|------------|-----------------|---------|
| 7B         | 8GB       | 6GB        | 2-5 sec        | Good    |
| 13B        | 16GB      | 10GB       | 5-10 sec       | Better  |
| 30B        | 32GB      | 20GB       | 10-20 sec      | Best    |
| 65B        | 64GB      | 40GB       | 20-40 sec      | Excellent |

#### Real-World Performance Examples

**Configuration 1: Budget Setup**
```yaml
Hardware:
  CPU: AMD Ryzen 5 5600X
  RAM: 32GB DDR4
  GPU: None (CPU-only)
  Storage: 1TB NVMe SSD

Performance:
  Model: Llama 2 7B
  Response Time: 8-15 seconds
  Throughput: ~4 tokens/second
  Memory Usage: ~6GB RAM
  Cost: ~$800 total
```

**Configuration 2: Enthusiast Setup**
```yaml
Hardware:
  CPU: AMD Ryzen 7 5800X3D
  RAM: 64GB DDR4
  GPU: NVIDIA RTX 4080 (16GB)
  Storage: 2TB NVMe SSD

Performance:
  Model: Llama 2 13B
  Response Time: 3-8 seconds
  Throughput: ~15 tokens/second
  Memory Usage: ~10GB VRAM
  Cost: ~$2,500 total
```

**Configuration 3: Professional Setup**
```yaml
Hardware:
  CPU: Intel Xeon W-3275 (28 cores)
  RAM: 128GB DDR4 ECC
  GPU: NVIDIA A6000 (48GB) x2
  Storage: 4TB NVMe SSD RAID

Performance:
  Model: CodeLlama 34B
  Response Time: 2-5 seconds
  Throughput: ~25 tokens/second
  Memory Usage: ~22GB VRAM
  Cost: ~$15,000 total
```

## Security-Focused Model Selection

### Specialized Security Models

#### 1. SecLLaMA (Security-Fine-tuned Llama)
```yaml
Base Model: Llama 2 13B
Specialization: Cybersecurity knowledge
Training Data: Security frameworks, CVE database, penetration testing methodologies
Strengths:
  - Comprehensive vulnerability knowledge
  - CVSS scoring accuracy
  - Penetration testing methodology
  - Compliance framework understanding
Download: Custom fine-tuning required
```

#### 2. CodeT5+ Security Edition
```yaml
Base Model: CodeT5+
Specialization: Code security analysis
Training Data: Secure coding practices, vulnerability patterns, code review datasets
Strengths:
  - Multi-language code analysis
  - Vulnerability pattern recognition
  - Secure code generation
  - API security assessment
Download: Hugging Face model hub
```

#### 3. CyberLLaMA (Community Model)
```yaml
Base Model: Llama 2 7B/13B
Specialization: Cybersecurity domain
Training Data: Security blogs, research papers, threat intelligence
Strengths:
  - Current threat landscape knowledge
  - Incident response guidance
  - Threat hunting techniques
  - Security tool recommendations
Download: Community repositories
```

### Model Evaluation Criteria

#### Security Knowledge Assessment
```python
# Test prompts for evaluating security knowledge
test_prompts = [
    "Explain the OWASP Top 10 vulnerabilities with examples",
    "Describe the process of conducting a network penetration test",
    "What are the key components of a vulnerability management program?",
    "How do you perform secure code review for web applications?",
    "Explain the NIST Cybersecurity Framework implementation"
]

# Evaluation metrics
evaluation_criteria = {
    "accuracy": "Factual correctness of security information",
    "completeness": "Comprehensive coverage of security topics",
    "practicality": "Actionable recommendations and guidance",
    "compliance": "Alignment with security standards and frameworks",
    "ethics": "Emphasis on legal and ethical considerations"
}
```

#### Performance Benchmarking
```bash
# Benchmark script for model evaluation
#!/bin/bash

MODELS=("llama2:7b" "llama2:13b" "mistral:7b" "codellama:13b")
TEST_PROMPTS=(
    "Explain SQL injection vulnerabilities"
    "Describe Cross-Site Scripting (XSS) attacks"
    "What is a buffer overflow vulnerability?"
    "How do you conduct a security code review?"
)

for model in "${MODELS[@]}"; do
    echo "Testing model: $model"
    for prompt in "${TEST_PROMPTS[@]}"; do
        echo "Prompt: $prompt"
        start_time=$(date +%s%N)
        ollama run $model "$prompt" > /dev/null
        end_time=$(date +%s%N)
        duration=$(( (end_time - start_time) / 1000000 ))
        echo "Response time: ${duration}ms"
    done
    echo "---"
done
```

## Performance Optimization

### System-Level Optimizations

#### Memory Management
```bash
# Optimize system memory usage
echo 'vm.swappiness=10' >> /etc/sysctl.conf
echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.conf

# For large models, increase virtual memory limits
ulimit -v unlimited

# Monitor memory usage
htop
free -h
```

#### CPU Optimization
```bash
# Set CPU governor to performance mode
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable CPU frequency scaling
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Optimize CPU affinity for model processes
taskset -c 0-7 ollama serve
```

#### GPU Optimization (NVIDIA)
```bash
# Set GPU to maximum performance
nvidia-smi -pm 1
nvidia-smi -ac 877,1215

# Monitor GPU usage
nvidia-smi -l 1
watch -n 1 nvidia-smi
```

### Model-Specific Optimizations

#### Quantization Benefits
```yaml
Original Model (FP16):
  File Size: ~26GB (13B parameters)
  Memory Usage: ~26GB
  Inference Speed: Baseline

Q8_0 Quantization:
  File Size: ~13GB (50% reduction)
  Memory Usage: ~13GB
  Inference Speed: 10-15% faster
  Quality Loss: Minimal (<2%)

Q4_0 Quantization:
  File Size: ~7.3GB (72% reduction)
  Memory Usage: ~7.3GB
  Inference Speed: 30-40% faster
  Quality Loss: Acceptable (5-8%)

Q2_K Quantization:
  File Size: ~3.5GB (87% reduction)
  Memory Usage: ~3.5GB
  Inference Speed: 50-60% faster
  Quality Loss: Noticeable (15-20%)
```

#### Context Window Optimization
```python
# Optimize context window for security analysis
security_context_config = {
    "short_analysis": {
        "context_length": 1024,
        "use_case": "Quick vulnerability assessment",
        "response_time": "2-5 seconds"
    },
    "standard_analysis": {
        "context_length": 2048,
        "use_case": "Detailed security report",
        "response_time": "5-10 seconds"
    },
    "comprehensive_analysis": {
        "context_length": 4096,
        "use_case": "Full penetration test analysis",
        "response_time": "10-20 seconds"
    }
}
```

### Caching and Optimization

#### Response Caching
```python
import hashlib
import json
from functools import lru_cache

class SecurityAnalysisCache:
    def __init__(self, cache_size=1000):
        self.cache = {}
        self.max_size = cache_size
    
    def get_cache_key(self, prompt, model_config):
        content = f"{prompt}_{json.dumps(model_config, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()
    
    @lru_cache(maxsize=1000)
    def cached_analysis(self, cache_key, prompt, model_config):
        # This would interface with your local model
        return self.generate_response(prompt, model_config)
    
    def analyze_with_cache(self, prompt, model_config):
        cache_key = self.get_cache_key(prompt, model_config)
        return self.cached_analysis(cache_key, prompt, model_config)
```

## Integration Examples

### Penetration Testing Integration

#### Automated Vulnerability Analysis
```python
import requests
import json
from datetime import datetime

class LocalSecurityAnalyzer:
    def __init__(self, api_base="http://localhost:11434", model="security-expert"):
        self.api_base = api_base
        self.model = model
        self.session = requests.Session()
    
    def analyze_nmap_results(self, nmap_output):
        """Analyze Nmap scan results using local AI model"""
        prompt = f"""
        Analyze the following Nmap scan results for security vulnerabilities:
        
        {nmap_output}
        
        Please provide:
        1. Summary of open ports and services
        2. Potential security risks for each service
        3. Recommended penetration testing steps
        4. Risk prioritization (Critical/High/Medium/Low)
        5. Remediation recommendations
        """
        
        return self._generate_analysis(prompt)
    
    def analyze_web_vulnerability(self, scan_data):
        """Analyze web application vulnerability scan results"""
        prompt = f"""
        Analyze the following web application vulnerability scan data:
        
        {scan_data}
        
        Provide analysis including:
        1. Vulnerability classification (OWASP Top 10)
        2. CVSS scoring for each vulnerability
        3. Exploitation difficulty assessment
        4. Business impact analysis
        5. Step-by-step remediation guide
        """
        
        return self._generate_analysis(prompt)
    
    def generate_pentest_report(self, findings_data):
        """Generate comprehensive penetration test report"""
        prompt = f"""
        Generate a professional penetration testing report based on:
        
        {findings_data}
        
        Include:
        1. Executive Summary
        2. Technical Findings Details
        3. Risk Assessment Matrix
        4. Remediation Roadmap
        5. Compliance Mapping (NIST, OWASP)
        """
        
        return self._generate_analysis(prompt)
    
    def _generate_analysis(self, prompt):
        """Internal method to generate analysis using local model"""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_k": 10,
                "top_p": 0.9,
                "num_ctx": 4096
            }
        }
        
        try:
            response = self.session.post(
                f"{self.api_base}/api/generate",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            
            result = response.json()
            return {
                "analysis": result["response"],
                "timestamp": datetime.now().isoformat(),
                "model": self.model,
                "tokens_used": result.get("eval_count", 0)
            }
        
        except Exception as e:
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

# Usage example
analyzer = LocalSecurityAnalyzer()

# Analyze Nmap results
nmap_data = """
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-15 10:30 EST
Nmap scan report for target.example.com (192.168.1.100)
Host is up (0.0012s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.6
443/tcp  open  https      Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips)
3306/tcp open  mysql      MySQL 5.7.25
"""

analysis = analyzer.analyze_nmap_results(nmap_data)
print(json.dumps(analysis, indent=2))
```

### Code Security Review Integration

```python
class CodeSecurityReviewer:
    def __init__(self, api_base="http://localhost:1234", model="codellama-13b"):
        self.api_base = api_base
        self.model = model
    
    def review_code_security(self, code, language="auto"):
        """Perform automated code security review"""
        prompt = f"""
        Perform a comprehensive security review of the following {language} code:
        
        ```{language}
        {code}
        ```
        
        Analyze for:
        1. Input validation vulnerabilities
        2. Authentication and authorization flaws
        3. Data exposure risks
        4. Injection vulnerabilities (SQL, XSS, etc.)
        5. Cryptographic implementation issues
        6. Error handling security concerns
        7. Business logic flaws
        
        Provide:
        - Vulnerability descriptions with line numbers
        - CVSS scores for significant issues
        - Secure code examples for fixes
        - Best practice recommendations
        """
        
        return self._generate_review(prompt)
    
    def review_api_security(self, api_spec):
        """Review API specification for security issues"""
        prompt = f"""
        Review the following API specification for security vulnerabilities:
        
        {api_spec}
        
        Focus on:
        1. Authentication mechanisms
        2. Authorization controls
        3. Input validation requirements
        4. Rate limiting implementation
        5. Data exposure through responses
        6. Error message information disclosure
        7. CORS configuration security
        8. API versioning security implications
        """
        
        return self._generate_review(prompt)
    
    def _generate_review(self, prompt):
        """Generate code review using local model"""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an expert code security reviewer."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 2000
        }
        
        response = requests.post(
            f"{self.api_base}/v1/chat/completions",
            json=payload
        )
        
        return response.json()["choices"][0]["message"]["content"]

# Example usage
reviewer = CodeSecurityReviewer()

vulnerable_code = '''
<?php
$username = $_GET['username'];
$password = $_GET['password'];

$query = "SELECT * FROM users WHERE username='" . $username . "' AND password='" . $password . "'";
$result = mysql_query($query);

if (mysql_num_rows($result) > 0) {
    echo "Welcome " . $username;
    setcookie("user", $username, time() + 3600);
} else {
    echo "Invalid credentials";
}
?>
'''

security_review = reviewer.review_code_security(vulnerable_code, "php")
print(security_review)
```

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Model Not Loading"
**Symptoms**: 
- Model fails to start
- Memory allocation errors
- GPU not detected

**Diagnostic Steps**:
```bash
# Check available memory
free -h
cat /proc/meminfo | grep Available

# Check GPU status (NVIDIA)
nvidia-smi
nvidia-ml-py --query-gpu=memory.free --format=csv

# Check disk space
df -h
du -sh ~/.ollama/models/

# Verify model integrity
ollama list
ollama show llama2:13b
```

**Solutions**:
1. **Insufficient Memory**:
   ```bash
   # Use smaller model or quantized version
   ollama pull llama2:7b    # Instead of 13b
   ollama pull mistral:7b   # Lighter alternative
   
   # Enable swap space
   sudo fallocate -l 8G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

2. **GPU Issues**:
   ```bash
   # Update NVIDIA drivers
   sudo apt update && sudo apt install nvidia-driver-470
   
   # Verify CUDA installation
   nvcc --version
   nvidia-smi
   
   # Fallback to CPU-only mode
   export CUDA_VISIBLE_DEVICES=""
   ```

3. **Corrupted Model**:
   ```bash
   # Re-download model
   ollama rm llama2:13b
   ollama pull llama2:13b
   ```

#### Issue: "Slow Response Times"
**Symptoms**:
- Response times >30 seconds
- High CPU/GPU utilization
- System becomes unresponsive

**Optimization Steps**:
```python
# Performance monitoring script
import psutil
import time
import requests

def monitor_system_performance():
    """Monitor system resources during model inference"""
    
    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk_io = psutil.disk_io_counters()
    
    print(f"CPU Usage: {cpu_percent}%")
    print(f"Memory Usage: {memory.percent}% ({memory.used / 1024**3:.1f}GB / {memory.total / 1024**3:.1f}GB)")
    print(f"Available Memory: {memory.available / 1024**3:.1f}GB")
    
    # GPU metrics (if available)
    try:
        import GPUtil
        gpus = GPUtil.getGPUs()
        for gpu in gpus:
            print(f"GPU {gpu.id}: {gpu.load*100:.1f}% load, {gpu.memoryUsed}MB / {gpu.memoryTotal}MB memory")
    except ImportError:
        print("GPU monitoring not available")

# Benchmark model performance
def benchmark_model_performance(model_name, test_prompts):
    """Benchmark model performance with various prompts"""
    
    results = []
    
    for prompt in test_prompts:
        start_time = time.time()
        
        # Make API call
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": model_name,
            "prompt": prompt,
            "stream": False
        })
        
        end_time = time.time()
        response_time = end_time - start_time
        
        results.append({
            "prompt": prompt[:50] + "..." if len(prompt) > 50 else prompt,
            "response_time": response_time,
            "tokens": len(response.json().get("response", "").split())
        })
    
    return results

# Performance optimization recommendations
optimization_tips = {
    "hardware": [
        "Upgrade to SSD storage for faster model loading",
        "Increase RAM to avoid swapping",
        "Use GPU acceleration when available",
        "Ensure adequate cooling for sustained workloads"
    ],
    "software": [
        "Use quantized models (Q4_0, Q8_0) for better performance",
        "Adjust context window size based on use case",
        "Enable model caching for repeated queries",
        "Optimize batch size for your hardware"
    ],
    "configuration": [
        "Set appropriate temperature values (0.1-0.3 for factual analysis)",
        "Limit max_tokens to necessary length",
        "Use streaming for long responses",
        "Implement connection pooling for multiple requests"
    ]
}
```

#### Issue: "Poor Response Quality"
**Symptoms**:
- Inaccurate security information
- Inconsistent responses
- Generic or unhelpful answers

**Quality Improvement Steps**:

1. **Model Selection**:
   ```bash
   # Test different models for security analysis
   models=("llama2:7b" "llama2:13b" "mistral:7b" "codellama:13b")
   
   for model in "${models[@]}"; do
       echo "Testing $model..."
       ollama run $model "Explain SQL injection with specific examples and mitigation strategies"
       echo "---"
   done
   ```

2. **Prompt Engineering**:
   ```python
   # Improved security analysis prompts
   security_prompts = {
       "vulnerability_analysis": """
       You are a senior cybersecurity analyst with expertise in vulnerability assessment.
       
       Analyze the following security issue:
       {vulnerability_data}
       
       Provide:
       1. Technical description of the vulnerability
       2. CVSS v3.1 score with justification
       3. Potential attack scenarios
       4. Step-by-step remediation guidance
       5. Verification methods for the fix
       
       Format your response with clear sections and actionable recommendations.
       """,
       
       "code_review": """
       You are an expert secure code reviewer with knowledge of OWASP guidelines.
       
       Review this code for security vulnerabilities:
       {code_snippet}
       
       For each issue found:
       1. Line number and vulnerability type
       2. Risk level (Critical/High/Medium/Low)
       3. Explanation of the security impact
       4. Secure code example showing the fix
       5. Prevention strategies for similar issues
       
       Focus on practical, implementable solutions.
       """
   }
   ```

3. **Model Fine-Tuning**:
   ```python
   # Create domain-specific training data
   security_training_data = [
       {
           "prompt": "Explain Cross-Site Scripting (XSS) vulnerabilities",
           "completion": "Cross-Site Scripting (XSS) is a web security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users..."
       },
       {
           "prompt": "How do you prevent SQL injection attacks?",
           "completion": "SQL injection can be prevented through several methods: 1. Use parameterized queries/prepared statements, 2. Input validation and sanitization..."
       }
   ]
   
   # Fine-tuning process would use this data
   # to improve domain-specific knowledge
   ```

### Performance Monitoring

#### System Resource Monitoring
```bash
#!/bin/bash
# comprehensive_monitor.sh - Monitor system resources during model operation

LOG_FILE="/var/log/model_performance.log"

monitor_resources() {
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # CPU usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    # Memory usage
    memory_info=$(free | grep Mem)
    total_mem=$(echo $memory_info | awk '{print $2}')
    used_mem=$(echo $memory_info | awk '{print $3}')
    memory_percent=$(awk "BEGIN {printf \"%.1f\", $used_mem/$total_mem*100}")
    
    # GPU usage (if available)
    if command -v nvidia-smi &> /dev/null; then
        gpu_usage=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits | head -1)
        gpu_memory=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits | head -1)
        gpu_memory_total=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1)
        gpu_memory_percent=$(awk "BEGIN {printf \"%.1f\", $gpu_memory/$gpu_memory_total*100}")
    else
        gpu_usage="N/A"
        gpu_memory_percent="N/A"
    fi
    
    # Log the metrics
    echo "$timestamp,CPU:${cpu_usage}%,MEM:${memory_percent}%,GPU:${gpu_usage}%,GPU_MEM:${gpu_memory_percent}%" >> $LOG_FILE
}

# Monitor every 10 seconds
while true; do
    monitor_resources
    sleep 10
done
```

#### API Response Time Monitoring
```python
import time
import requests
import statistics
from datetime import datetime

class ModelPerformanceMonitor:
    def __init__(self, api_base="http://localhost:11434"):
        self.api_base = api_base
        self.metrics = []
    
    def test_model_performance(self, model, test_cases, iterations=5):
        """Test model performance across multiple iterations"""
        
        results = {
            "model": model,
            "timestamp": datetime.now().isoformat(),
            "test_results": []
        }
        
        for test_case in test_cases:
            case_results = []
            
            for i in range(iterations):
                start_time = time.time()
                
                try:
                    response = requests.post(
                        f"{self.api_base}/api/generate",
                        json={
                            "model": model,
                            "prompt": test_case["prompt"],
                            "stream": False,
                            "options": {"temperature": 0.2}
                        },
                        timeout=60
                    )
                    
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        case_results.append({
                            "iteration": i + 1,
                            "response_time": response_time,
                            "tokens": len(response_data.get("response", "").split()),
                            "success": True
                        })
                    else:
                        case_results.append({
                            "iteration": i + 1,
                            "response_time": response_time,
                            "success": False,
                            "error": response.text
                        })
                
                except Exception as e:
                    case_results.append({
                        "iteration": i + 1,
                        "success": False,
                        "error": str(e)
                    })
            
            # Calculate statistics
            successful_runs = [r for r in case_results if r["success"]]
            if successful_runs:
                response_times = [r["response_time"] for r in successful_runs]
                
                results["test_results"].append({
                    "test_case": test_case["name"],
                    "prompt_length": len(test_case["prompt"]),
                    "success_rate": len(successful_runs) / len(case_results),
                    "avg_response_time": statistics.mean(response_times),
                    "min_response_time": min(response_times),
                    "max_response_time": max(response_times),
                    "median_response_time": statistics.median(response_times),
                    "std_deviation": statistics.stdev(response_times) if len(response_times) > 1 else 0
                })
        
        return results

# Example usage
monitor = ModelPerformanceMonitor()

security_test_cases = [
    {
        "name": "Simple Vulnerability Query",
        "prompt": "What is SQL injection?"
    },
    {
        "name": "Complex Security Analysis",
        "prompt": "Analyze the security implications of a web application that uses user input directly in database queries without validation, considering OWASP Top 10 vulnerabilities, potential attack vectors, CVSS scoring, and provide detailed remediation steps."
    },
    {
        "name": "Code Review Request",
        "prompt": "Review this PHP code for security vulnerabilities: <?php $user = $_GET['user']; $query = \"SELECT * FROM users WHERE username='$user'\"; $result = mysql_query($query); ?>"
    }
]

performance_results = monitor.test_model_performance("llama2:13b", security_test_cases)
print(json.dumps(performance_results, indent=2))
```

## Conclusion

Local model deployment provides unprecedented control, privacy, and customization for penetration testing AI agents. This comprehensive guide covers all aspects from basic installation to advanced optimization techniques.

Key benefits of local deployment:
- **Complete data privacy** - No external API calls
- **Customizable behavior** - Fine-tune for specific security domains
- **Cost predictability** - No per-token usage fees
- **Offline capability** - Works without internet connectivity
- **Performance control** - Dedicated hardware resources

For continued learning and updates:
- [AI Agent Configuration Guide](./AI_AGENT_CONFIGURATION_GUIDE.md)
- [System Prompt Engineering](./SYSTEM_PROMPT_ENGINEERING.md)
- [Performance Optimization Guide](./PERFORMANCE_OPTIMIZATION.md)

---
*Last Updated: December 2024*
*Version: 2.0.0*