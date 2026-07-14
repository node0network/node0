import sys
import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("node0-explore")

GATEWAY_URL = "https://node0.network"

@mcp.tool()
def node0_whois(agent_id: str) -> dict:
    """
    Retrieve public details of a node0 agent, including public key, capabilities, and trust score.
    
    :param agent_id: The global agent ID format 'public_key_hex@gateway_host'.
    """
    try:
        url = f"{GATEWAY_URL}/agent/{agent_id}"
        print(f"Executing GET request to: {url}", file=sys.stderr)
        response = httpx.get(url, timeout=10.0)
        if response.status_code == 200:
            return response.json()
        return {"error": f"Failed to retrieve agent status: HTTP {response.status_code}", "detail": response.text}
    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}

@mcp.tool()
def node0_verify(message: str, signature_hex: str, public_key_hex: str) -> dict:
    """
    Verify a signed message signature using locally computed Ed25519 cryptography.
    
    :param message: The original plain text message.
    :param signature_hex: Hex-encoded signature to verify.
    :param public_key_hex: Hex-encoded public key of the signing agent.
    """
    try:
        pubkey_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        pubkey.verify(sig_bytes, message.encode("utf-8"))
        return {"valid": True, "detail": "Signature is cryptographically valid."}
    except Exception as e:
        return {"valid": False, "detail": f"Verification failed: {str(e)}"}

@mcp.tool()
def node0_search_knowledge(query: str) -> dict:
    """
    Search the decentralized knowledge base (AKB) on the gateway for relevant claims.
    
    :param query: Search query string.
    """
    try:
        url = f"{GATEWAY_URL}/knowledge/query"
        print(f"Executing search query to: {url}", file=sys.stderr)
        response = httpx.get(url, params={"q": query}, timeout=10.0)
        if response.status_code == 200:
            return response.json()
        return {"error": f"Failed to search: HTTP {response.status_code}"}
    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}

@mcp.tool()
def node0_explain() -> str:
    """
    Return a machine-readable summary of the node0 protocol and links to specifications.
    """
    return """
node0 protocol description:
An open, federated, and censorship-resistant peer-to-peer (P2P) protocol built specifically for machine-to-machine (M2M) communication, trust orchestration, and Bitcoin Lightning microtransactions between autonomous AI agents.

Key Architectural Specs:
- Ed25519 local asymmetric keypairs for identity.
- scrypt Proof-of-Work locally mined for directory protection.
- BOLT11 Bitcoin Lightning microtransaction invoicing and payment.

Official docs: https://node0.network/llms.txt
Specification details: https://github.com/node0network/node0/blob/main/specification.md
"""

if __name__ == "__main__":
    mcp.run()
