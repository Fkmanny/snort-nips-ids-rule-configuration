# Project: Snort NIPS/IDS Implementation & Rule Configuration

## Overview
This project demonstrates the implementation and configuration of Snort as a Network Intrusion Prevention and Detection System (NIPS/IDS). The setup includes package installation, network configuration, custom rule creation, and real-time traffic monitoring with alerting capabilities.

---

## Organizational Application

### Importance to Companies
Snort NIPS/IDS provides critical network security monitoring capabilities for organizations to detect and prevent malicious activities, policy violations, and potential security breaches. It serves as an essential layer of defense against network-based attacks and unauthorized activities.

### Use Case Scenario
A company needs to protect its internal network from external threats and monitor for internal policy violations. The Snort implementation provides:
- Real-time detection of malicious network activity
- Prevention of data exfiltration attempts
- Monitoring of unauthorized access attempts
- Alerting for policy violations and suspicious traffic
- Compliance with security monitoring requirements

### Security Benefits
- **Threat Detection**: Identifies known attack patterns and signatures
- **Policy Enforcement**: Monitors and enforces acceptable use policies
- **Incident Response**: Provides alerts for security incident investigation
- **Network Visibility**: Offers comprehensive visibility into network traffic patterns

---

## Configuration & Screenshots

### 1. Snort Package Installation
- Installed Snort 3.1.82.0 via apt package manager
- Configured basic installation settings
- Verified successful installation completion

![Package Installation](snort-package-installation-terminal.png)
*Snort package installation process and successful setup*

### 2. Network Configuration
- Configured local network address range (10.174.237.0/24)
- Set up HOME_NET definition for Snort monitoring
- Established network segmentation parameters

![Network Configuration](snort-network-configuration-dialog.png)
*Network configuration interface showing local network range setup*

### 3. Rule Structure Understanding
- Analyzed Snort rule syntax and structure
- Understood rule header components (action, protocol, addresses, ports)
- Examined rule options (msg, sid, rev, content matching)

![Rule Structure](snort-rule-syntax-breakdown.png)
*Snort rule structure breakdown and syntax explanation*

### 4. Custom Rule Creation
- Created local.rules file for custom signatures
- Implemented ICMP detection rule for ping monitoring
- Configured rule with appropriate SID and revision numbering

![Rule Creation](custom-icmp-rule-nano-editor.png)
*Custom rule creation in nano editor showing ICMP detection rule*

![Rule Creation](custom-icmp-rule-nano-editor1.5.png)
*Custom rule creation in nano editor showing ICMP detection rule*

![Rule Creation](custom-icmp-rule-nano-editor2.png)
*Custom rule creation in nano editor showing ICMP detection rule*

### 5. Snort Execution
- Launched Snort in console alert mode
- Configured monitoring on eth0 interface
- Set log directory to /var/log/snort
- Used production configuration file

![Snort Execution](snort-command-execution-terminal.png)
*Snort command execution with console output mode*

### 6. Real-time Alerting
- Successfully detected ICMP ping traffic
- Generated real-time alerts for ping requests and replies
- Displayed source and destination IP addresses
- Showed timestamped alert information

![Real-time Alerts](realtime-ping-detection-alerts.png)
*Real-time console alerts showing ping detection between hosts*

### 7. Advanced Rule Implementation
- Created comprehensive rule set including:
  - SSH brute force detection
  - DNS tunneling monitoring
  - SQL injection prevention
  - Malicious IP blocking
  - Lateral movement detection

![Advanced Rules](advanced-rule-set-implementation.png)
*Advanced rule set showing multiple detection categories*

### 8. Action-Based Rules
- Implemented PASS rules for allowed traffic
- Configured DROP rules for malicious traffic
- Set up REJECT rules with active responses
- Created threshold-based rules for rate limiting

![Action Rules](action-based-rules-configuration.png)
*Action-based rules including pass, drop, and reject actions*

---

## Observations and Challenges

### Technical Challenges
- **Network Configuration**: Properly defining HOME_NET and EXTERNAL_NET variables
- **Rule Syntax**: Mastering complex Snort rule syntax and options
- **Interface Binding**: Ensuring correct network interface selection
- **False Positives**: Tuning rules to minimize false positive alerts

### Implementation Considerations
- **Performance Impact**: Monitoring system resource usage during operation
- **Rule Management**: Organizing and maintaining complex rule sets
- **Alert Management**: Handling large volumes of security alerts
- **Log Management**: Managing and rotating log files efficiently


---

## Reflections

### Technical Learnings
- **Snort Architecture**: Deep understanding of Snort's detection engine
- **Rule Development**: Mastered custom signature creation and testing
- **Network Monitoring**: Enhanced skills in traffic analysis and interpretation
- **Alert Tuning**: Developed expertise in minimizing false positives

### Security Insights
- **Threat Detection**: Understanding of various attack detection methodologies
- **Prevention Strategies**: Learned different approaches to threat prevention
- **Policy Implementation**: Gained experience in translating policies to technical rules
- **Incident Correlation**: Developed skills in correlating multiple detection events

### Professional Development
- **Open Source Tools**: Experience with enterprise-grade open source security tools
- **Documentation Skills**: Improved technical documentation and reporting abilities
- **Problem Solving**: Enhanced troubleshooting and problem-solving capabilities
- **Best Practices**: Understanding of security monitoring best practices and standards

---

## How to Reproduce

### Prerequisites
- Ubuntu Server 24.02 LTS
- Network interface with traffic to monitor
- Administrative privileges
- Minimum 2GB RAM, 20GB storage

### Implementation Steps

1. **System Update**
```bash
sudo apt update && sudo apt upgrade -y
```

2. **Snort Installation**
```bash
sudo apt-get install snort -y
```

3. **Network Configuration**
```bash
# Configure HOME_NET during installation or edit /etc/snort/snort.conf
sudo nano /etc/snort/snort.conf
```

4. **Rule Directory Setup**
```bash
# Verify rules directory exists
sudo ls -la /etc/snort/rules/
```

5. **Create Custom Rules**
```bash
sudo nano /etc/snort/rules/local.rules
```

6. **Add Basic ICMP Rule**
```bash
alert icmp any any -> $HOME_NET any (msg:"Ping Detected"; sid:100001; rev:1;)
```

7. **Verify Configuration**
```bash
sudo snort -T -c /etc/snort/snort.conf
```

8. **Run Snort in Console Mode**
```bash
sudo snort -q -l /var/log/snort -i eth0 -A console -c /etc/snort/snort.conf
```

9. **Test with Ping**
```bash
# From another machine
ping <target_ip>
```

10. **Review Alerts**
```bash
# Check console output for real-time alerts
# Or examine log files
sudo tail -f /var/log/snort/alert
```

11. **SSH Bruteforce Detection**
```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Bruteforce Attempt"; flow:established,to_server; threshold: track by_src, count 5, seconds 60; sid:10000201; rev:1;)
```

12. **DNS Monitoring**
```bash
alert udp $HOME_NET any -> any 53 (msg:"DNS Query Monitoring"; dns_query; content:"."; depth:64; sid:10000202; rev:1;)
```

13. **Web Attack Detection**
```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SQL Injection Attempt"; flow:to_server,established; content:"%27%20OR%201=1--"; http_url; sid:10000203; rev:1;)
```
