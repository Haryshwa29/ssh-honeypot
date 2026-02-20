# SSH Honeypot – Docker-Based Medium Interaction

A medium-interaction SSH honeypot designed to capture attacker behavior in a controlled and isolated environment.

This project simulates an exposed SSH service, dynamically provisions isolated Docker containers per session, and logs attacker activity for behavioral analysis.

---

## Overview

This honeypot was built to:

- Observe real-world SSH attack patterns
- Capture command execution behavior
- Study brute-force and post-compromise actions
- Practice secure system isolation and logging design

The system is intentionally designed with strong containment controls to prevent attacker pivoting or outbound abuse.

---

## Architecture

Attacker (e.g., Kali Linux)
        ↓
Python SSH Manager (Port 2222)
        ↓
Ephemeral Docker Container (Isolated Network)
        ↓
Command & Session Logs (Host Storage)

Each attacker session is isolated inside a temporary Docker container attached to an internal bridge network.

---

## Key Features

- Custom Python-based SSH session manager
- Dynamic Docker container spawning per connection
- Internal Docker bridge network (no outbound internet)
- Session-level isolation
- Command logging and transcript storage
- Host-level log persistence
- Configurable settings via YAML

---

## Security Design Principles

- Containers run on an internal Docker network
- No direct outbound internet access from attacker container
- No host filesystem exposure
- No credential reuse
- Session logs stored outside container
- Minimal attack surface inside target container

The design ensures attacker interaction remains contained and observable.

---

## Project Structure

ssh-honeypot/
├── src/ # SSH manager logic
├── infra/ # Docker and target container configs
├── config/ # Example configuration files
├── logs/ # Session logs (ignored in Git)
├── docs/ # Notes and documentation
├── config.yaml # Runtime configuration
├── README.md

## How To Run

1. Clone the repository
2. Build the target Docker image: ./infra/build_image.sh
3. Create internal network: docker network create --driver bridge --internal honeynet
4. Start manager:python src/manager.py
5. Connect from attacker machine:ssh -p 2222 user@HOST_IP

## Example Use Case

This honeypot can be used to:

- Study SSH brute-force patterns
- Analyze attacker post-login behavior
- Capture command sequences for research
- Test defensive monitoring systems
- Demonstrate container-based isolation techniques

---

## Future Improvements

- GeoIP enrichment of attacker IPs
- Automated credential harvesting analysis
- Web-based dashboard for log visualization
- SIEM integration
- Behavioral pattern clustering

---

## Disclaimer

This project is intended strictly for educational and research purposes.

Deploy responsibly. Do not expose to production environments without proper legal authorization.
