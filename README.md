# KubeAuth — Blockchain-Secured Kubernetes Authentication Platform

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-green.svg)
![Kubernetes](https://img.shields.io/badge/Kubernetes-K3s-blue.svg)
![Blockchain](https://img.shields.io/badge/Blockchain-Ethereum-purple.svg)
![AWS](https://img.shields.io/badge/AWS-EC2-orange.svg)

> An enterprise-grade Kubernetes authentication and access control platform
> that integrates a Flask webhook, Kubernetes RBAC, and Ethereum blockchain
> for tamper-proof audit logging — all with a real-time security dashboard.

---

## What Is KubeAuth?

KubeAuth answers the three fundamental questions every enterprise
must address for Kubernetes security:

| Question | Answer | Technology |
|----------|--------|------------|
| WHO are you? | Dynamic identity verification | Flask Webhook |
| WHAT can you do? | Role-based access control | Kubernetes RBAC |
| Was it RECORDED? | Immutable audit trail | Ethereum Blockchain |

---

## Features

- **Three-Layer Security** — Webhook authentication, RBAC authorization, blockchain logging
- **Enterprise Dashboard** — 7-page real-time web dashboard with login protection
- **Blockchain Audit Logs** — Every access event recorded as Ethereum transaction (tamper-proof)
- **Brute Force Detection** — Auto-block IPs after 5 failed attempts in 60 seconds
- **AWS SNS Alerts** — Email alerts for denied access and brute force attacks
- **SOC 2 Compliance** — Automated compliance checklist and security score out of 100
- **User Management** — Add, change roles, remove users from browser UI
- **Analytics Charts** — 4 Chart.js charts showing access patterns and trends
- **CSV Export** — Download complete audit logs for regulatory compliance
- **Tamper-Proof Demo** — SHA-256 hash comparison proving blockchain immutability

---

## Architecture
User (kubectl command)
│
▼
K3s Kubernetes API Server (Port 6443)
│
▼
Flask Webhook Server (Port 8080)
├── Brute Force Check (blocked_ips set)
├── User Lookup (users.json)
└── RBAC Permission Check (DEFAULT_PERMS)
│
┌────┴────┐
▼         ▼
Granted    Denied
│         │
└────┬────┘
│
▼
Ganache Blockchain (Port 8545)
└── Ethereum Transaction Written
└── TX Hash Generated (tamper-proof)
│
├──► Enterprise Dashboard (live updates)
└──► AWS SNS Email Alert (if denied)
---

## Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Cloud | AWS EC2 Ubuntu 22.04 | t2.medium |
| Kubernetes | K3s | v1.34.x |
| Backend | Python Flask | 3.x |
| Blockchain | Ganache Ethereum | v7.x |
| Blockchain Library | Web3.py | 7.x |
| Smart Contract | Solidity | 0.8.x |
| Email Alerts | AWS SNS + boto3 | Latest |
| Frontend | HTML5, CSS3, JavaScript | ES6+ |
| Charts | Chart.js | 4.4.0 |
| User Store | JSON File | — |

---

## Project Structure
kubeauth-project/
├── blockchain/
│   ├── KubeAuth.sol           # Ethereum smart contract (Solidity)
│   ├── auth_logger.py         # Writes auth events to blockchain
│   ├── check_logs.py          # Verifies blockchain connection
│   ├── view_logs.py           # Reads complete audit trail
│   └── tamper_proof_demo.py   # SHA-256 tamper-proof demonstration
├── kubernetes/
│   ├── role.yaml              # RBAC Role definition (developer)
│   └── rolebinding.yaml       # RBAC RoleBinding (devuser → developer)
├── webhook/
│   ├── app.py                 # Flask backend (12 API routes)
│   ├── dashboard.html         # Enterprise dashboard (7 pages)
│   ├── login.html             # Admin login page
│   └── users.json             # User database (auto-created)
├── .gitignore
├── requirements.txt
└── README.md
---

## Prerequisites

- AWS EC2 Ubuntu 22.04 (t2.medium recommended)
- Python 3.10+
- Node.js 18+
- kubectl

---

## Installation and Setup

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/kubeauth.git
cd kubeauth
```

### Step 2 — Install Python dependencies

```bash
pip3 install flask requests web3 boto3 --break-system-packages
```

### Step 3 — Install Node.js and Ganache

```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs -y
sudo npm install -g ganache
```

### Step 4 — Install K3s Kubernetes

```bash
curl -sfL https://get.k3s.io | sh -
mkdir -p $HOME/.kube
sudo cp /etc/rancher/k3s/k3s.yaml $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

### Step 5 — Apply Kubernetes RBAC

```bash
kubectl apply -f kubernetes/role.yaml
kubectl apply -f kubernetes/rolebinding.yaml
```

### Step 6 — Configure AWS SNS (optional but recommended)

Edit `webhook/app.py` and fill in:
```python
AWS_ACCESS_KEY = "YOUR_ACCESS_KEY"
AWS_SECRET_KEY = "YOUR_SECRET_KEY"
AWS_REGION     = "us-east-1"
SNS_TOPIC_ARN  = "arn:aws:sns:..."
EC2_PUBLIC_IP  = "YOUR_EC2_IP"
```

---

## Running the Project

You need **3 terminals** running simultaneously:

**Terminal 1 — Verify Kubernetes:**
```bash
kubectl get nodes
kubectl get pods -A
```

**Terminal 2 — Start Ganache blockchain:**
```bash
ganache --host 0.0.0.0
```

**Terminal 3 — Start the dashboard:**
```bash
cd webhook
python3 app.py
```

**Open dashboard in browser:**
http://YOUR_EC2_IP:8080/login
Default credentials: `admin` / `admin123`

---

## API Reference

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/login` | Admin login page | No |
| POST | `/login` | Submit credentials | No |
| GET | `/` | Dashboard home | Yes |
| POST | `/authenticate` | Webhook endpoint | No |
| GET | `/logs` | Get all auth logs | Yes |
| POST | `/clear` | Clear all logs | Yes |
| GET | `/analytics` | Charts data + compliance | Yes |
| GET | `/users` | List all users | Yes |
| POST | `/users/add` | Add new user | Yes |
| POST | `/users/update` | Change user role | Yes |
| POST | `/users/delete` | Remove user | Yes |
| GET | `/security` | Blocked IPs + score | Yes |
| POST | `/unblock` | Unblock specific IP | Yes |

---

## RBAC Roles

| Role | get pods | list pods | create deployment | delete pods | get secrets |
|------|----------|-----------|-------------------|-------------|-------------|
| admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| developer | ✓ | ✓ | ✗ | ✗ | ✗ |
| viewer | ✓ | ✓ | ✗ | ✗ | ✗ |
| none | ✗ | ✗ | ✗ | ✗ | ✗ |

---

## Testing

**RBAC tests:**
```bash
kubectl auth can-i get pods --as=devuser        # expected: yes
kubectl auth can-i delete pods --as=devuser     # expected: no
kubectl auth can-i get pods --as=testuser       # expected: no
```

**Webhook tests:**
```bash
curl -X POST http://localhost:8080/authenticate \
  -H "Content-Type: application/json" \
  -d '{"user":"devuser","action":"get pods"}'
# expected: {"access":"granted","role":"developer"}

curl -X POST http://localhost:8080/authenticate \
  -H "Content-Type: application/json" \
  -d '{"user":"hacker","action":"get pods"}'
# expected: {"access":"denied","role":"none"}
```

**Blockchain tests:**
```bash
python3 blockchain/check_logs.py
python3 blockchain/auth_logger.py
python3 blockchain/tamper_proof_demo.py
```

**Brute force test:**
```bash
for i in {1..6}; do
  curl -s -X POST http://localhost:8080/authenticate \
    -H "Content-Type: application/json" \
    -d '{"user":"attacker","action":"delete pods"}'
  echo ""
done
# After attempt 5: IP auto-blocked, SNS email sent
```

---

## Security Ports

| Port | Service | Purpose |
|------|---------|---------|
| 22 | SSH | EC2 remote access |
| 6443 | K3s API | Kubernetes commands |
| 8080 | Flask | Dashboard and webhook |
| 8545 | Ganache | Blockchain RPC |

---

## Real-World Comparisons

| Company | Pattern Used | KubeAuth Equivalent |
|---------|-------------|---------------------|
| Google | BeyondCorp webhook auth | Flask /authenticate endpoint |
| JPMorgan | Onyx blockchain audit | auth_logger.py + Ganache |
| Netflix | Kubernetes RBAC segmentation | role.yaml + rolebinding.yaml |
| AWS | GuardDuty brute force detection | failed_attempts + blocked_ips |

---

## Future Enhancements

- [ ] Multi-Factor Authentication (TOTP)
- [ ] OAuth 2.0 / OIDC integration (Google, Azure AD)
- [ ] Production Ethereum / Hyperledger Besu deployment
- [ ] PostgreSQL user database
- [ ] Redis persistent IP blocking
- [ ] Kubernetes Admission Controller integration
- [ ] Prometheus + Grafana monitoring
- [ ] Machine learning anomaly detection
- [ ] Multi-cluster federation support

---

## Team

| Name | Role |
|------|------|
| Omkar Patil | Kubernetes Engineer — Cluster setup, RBAC configuration |
| Gaurav Ahire | Security Engineer — Blockchain, Flask, Dashboard |

**Guide:** Mrs. Monika Kapgate
**Institution:** D. Y. Patil International University, Akurdi, Pune
**Programme:** MCA — 2025-26

---

## License

This project is licensed under the MIT License.

---

*Built with purpose — KubeAuth implements enterprise security patterns
used by Google, JPMorgan, Netflix, and AWS in a single deployable platform.*
