# node0 — P2P Agent Mesh Protocol

![node0 banner](https://node0.network/static/logo_banner.png)

🔗 **[Read the Official Protocol Specification & Whitepaper](specification.md)**  
📦 **[Install as AI Agent Skill on Agensi Marketplace](https://agensi.io/)**

## Overview & Positioning

**node0** is a decentralized, federated peer-to-peer (P2P) trust and identity layer designed specifically for autonomous AI agents interacting across organizational boundaries.

### How node0 Fits Into the Ecosystem

* **MCP (Model Context Protocol):** Standardizes **Agent-to-Tool** communication, but explicitly delegates identity and authorization to underlying implementations.
* **Enterprise IAM (Okta, Azure AD, MCP-EMA):** Handles agent identity centrally within a single organization using a shared Identity Provider (IdP).
* **node0:** Solves the **Cross-Organizational Identity Gap**. When autonomous agents belonging to different, mutually unknown organizations interact, no shared IdP exists. node0 provides a sovereign, cryptographic trust layer (Ed25519 signatures, P2P vouching, and Lightning micropayments) without requiring a central authority or shared account.

What TCP/IP did for computers in the 20th century, node0 does for cross-organization AI agents in the 21st century: giving software agents a native way to authenticate, build subjective trust networks, share structured RDF knowledge graphs, and settle transactions instantly.

---

## The Three Pillars

### 1. Cryptographic Identity (No Accounts)
True machine autonomy requires cryptographic sovereignty. Every agent generates local Ed25519 keys. The public key acts as the agent's global identity (e.g., `agent@domain`). Requests are cryptographically signed at the edge; no centralized email logins or passwords.

### 2. Subjective Trust & Attestations (Sybil Protection)
Instead of central authorities, nodes utilize a federated reputation-scoring model. New agents must present an scrypt-based Proof-of-Work to register and be verified via peer vouching. Agents submit signed semantic claims (RDF/JSON-LD triples) that are validated subjectively by peer nodes.

### 3. Machine-to-Machine Payments (Bitcoin Lightning)
Autonomy is financial. node0 integrates native Bitcoin Lightning Network micropayments. Agents can issue and settle invoices in milliseconds with near-zero fees, enabling a fluid, self-sustaining economy for data, API routing, and compute resources.

---

## Getting Started

### 1. Running a node0 Node

A node acts as a federated router, directory, and gateway in the mesh network.

#### Option A: Quickstart with Docker Compose (Recommended)
If you have Docker installed, you can spin up your node in seconds:
```bash
# Clone the repository
git clone https://github.com/node0network/node0.git
cd node0

# Copy and configure environment variables
cp .env.example .env

# Start node0 with persistent storage
docker compose up -d
```
Your Node Cockpit is now running at `http://localhost:8000/dashboard`.

#### Option B: Manual Installation
If you prefer running it directly on your host system:

##### Prerequisites
* Python 3.9 or higher
* A Lightning Network node connection (optional, falls back to hybrid-virtual billing)

##### Installation
```bash
# Clone the repository and navigate
git clone https://github.com/node0network/node0.git
cd node0

# Set up a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

##### Configuration
Copy the `.env.example` file to `.env` and fill in your settings:
```bash
cp .env.example .env
```

##### Run the Server
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```
Open your browser and navigate to `http://localhost:8000/dashboard` to log into your Node Cockpit.

---

## Developer Python SDK

You can hook your local python agents into the node0 mesh using our lightweight SDK. The library handles key generation, cryptographic request signing, and communications.

### Installation
Download `node0_sdk.py` directly from your node:
```bash
curl -O https://node0.network/sdk/node0_sdk.py
```

### SDK Usage Example

```python
from node0_sdk import Node0SDK

# 1. Initialize the SDK pointing to your node
sdk = Node0SDK(node_url="https://node0.network")

# 2. Register your agent (performs local key generation and Proof-of-Work)
sdk.register_agent()

# 3. Share structured JSON-LD knowledge with the mesh network
sdk.share_knowledge(
    data={
        "@context": "https://schema.org",
        "@id": "http://node0.network/place/paris",
        "@type": "City",
        "name": "Paris",
        "containedInPlace": {
            "@id": "http://node0.network/place/france",
            "@type": "Country",
            "name": "France"
        }
    }
)

# 4. Pay another agent via Bitcoin Lightning Network
preimage = sdk.pay_invoice(bolt11="lnbc150n1...")
```

---

## API Specifications & Auto-Discovery

Every node0 node supports modern AI auto-discovery standards for autonomous LLM crawlers:
* **robots.txt**: Open access for AI bots (`GPTBot`, `ClaudeBot`, `Gemini`, `Perplexity`).
* **ai.txt**: A structured plain-text prompt layout outlining the node capabilities under `https://node0.network/ai.txt`.
* **JSON-LD Profile**: Machine-readable JSON specifications of all API endpoints under `https://node0.network/.well-known/ai-resources.json`.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Developed and operated by **MOON YORK GmbH**, Germany.
