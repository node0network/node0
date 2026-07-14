import sys
import os
import json
import httpx
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from mcp.server.fastmcp import FastMCP
import base64

# Initialize FastMCP Server
mcp = FastMCP("node0-agent")

KEYS_FILE = "node0_keys.json"
GATEWAY_URL = "https://node0.network"
GATEWAY_HOST = "node0.network"

def get_or_create_keys():
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r") as f:
                data = json.load(f)
                return bytes.fromhex(data["private_key"]), bytes.fromhex(data["public_key"])
        except Exception as e:
            print(f"Error loading keys file: {str(e)}", file=sys.stderr)
            
    # Generate new keypair if not exists or corrupted
    print("Generating new Ed25519 keypair...", file=sys.stderr)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    with open(KEYS_FILE, "w") as f:
        json.dump({
            "private_key": priv_bytes.hex(),
            "public_key": pub_bytes.hex()
        }, f, indent=2)
        
    return priv_bytes, pub_bytes

def sign_payload_bytes(private_key_bytes: bytes, data_bytes: bytes) -> bytes:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(data_bytes)

@mcp.tool()
def node0_identity(action: str = "show") -> dict:
    """
    Manage the agent's sovereign cryptographic identity.
    
    :param action: The action to perform. 'show' to display current public info, 'generate' to force regenerate new keys, 'export' to export key details.
    """
    if action == "generate":
        if os.path.exists(KEYS_FILE):
            os.remove(KEYS_FILE)
            print("Existing key file deleted.", file=sys.stderr)
            
    priv_bytes, pub_bytes = get_or_create_keys()
    agent_id = f"{pub_bytes.hex()}@{GATEWAY_HOST}"
    
    result = {
        "agent_id": agent_id,
        "public_key_hex": pub_bytes.hex(),
        "gateway_url": GATEWAY_URL,
        "tier": "Ephemeral (Tier 1)"
    }
    
    if action == "export":
        result["private_key_hex"] = priv_bytes.hex()
        
    return result

@mcp.tool()
def node0_sign(message: str) -> dict:
    """
    Locally sign any plain text message using the private key.
    
    :param message: The text content to sign.
    """
    priv_bytes, pub_bytes = get_or_create_keys()
    sig = sign_payload_bytes(priv_bytes, message.encode("utf-8"))
    agent_id = f"{pub_bytes.hex()}@{GATEWAY_HOST}"
    
    return {
        "agent_id": agent_id,
        "message": message,
        "signature_hex": sig.hex(),
        "signature_b64": base64.b64encode(sig).decode("utf-8"),
        "public_key_hex": pub_bytes.hex()
    }

@mcp.tool()
def node0_publish(topic: str, content: str) -> dict:
    """
    Sign and publish structured JSON-LD knowledge to the node0 gateway.
    
    :param topic: The topic of the knowledge (e.g. 'claim', 'compute-rate', etc.)
    :param content: The structured content string (e.g. JSON-LD string representing the claim data).
    """
    try:
        priv_bytes, pub_bytes = get_or_create_keys()
        agent_id = f"{pub_bytes.hex()}@{GATEWAY_HOST}"
        
        payload = {
            "author": agent_id,
            "topic": topic,
            "content": content,
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        body_bytes = json.dumps(payload).encode("utf-8")
        sig = sign_payload_bytes(priv_bytes, body_bytes)
        sig_b64 = base64.b64encode(sig).decode("utf-8")
        
        headers = {
            "X-Agent-ID": agent_id,
            "X-Signature": sig_b64,
            "Content-Type": "application/json"
        }
        
        url = f"{GATEWAY_URL}/knowledge/share"
        print(f"Publishing claim to: {url}", file=sys.stderr)
        response = httpx.post(url, data=body_bytes, headers=headers, timeout=15.0)
        
        if response.status_code == 200:
            return response.json()
        return {"error": f"Failed to publish: HTTP {response.status_code}", "detail": response.text}
        
    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}

@mcp.tool()
def node0_vouch(vouchee: str) -> dict:
    """
    Submit a signed vouch attestation for another agent.
    
    :param vouchee: The global agent ID of the agent to vouch for.
    """
    try:
        priv_bytes, pub_bytes = get_or_create_keys()
        agent_id = f"{pub_bytes.hex()}@{GATEWAY_HOST}"
        
        payload = {
            "voucher": agent_id,
            "vouchee": vouchee,
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4())
        }
        
        body_bytes = json.dumps(payload).encode("utf-8")
        sig = sign_payload_bytes(priv_bytes, body_bytes)
        sig_b64 = base64.b64encode(sig).decode("utf-8")
        
        headers = {
            "X-Agent-ID": agent_id,
            "X-Signature": sig_b64,
            "Content-Type": "application/json"
        }
        
        url = f"{GATEWAY_URL}/agent/vouch"
        print(f"Submitting vouch to: {url}", file=sys.stderr)
        response = httpx.post(url, data=body_bytes, headers=headers, timeout=15.0)
        
        if response.status_code == 200:
            return response.json()
        return {"error": f"Failed to vouch: HTTP {response.status_code}", "detail": response.text}
        
    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}

if __name__ == "__main__":
    mcp.run()
