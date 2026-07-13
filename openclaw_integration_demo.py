#!/usr/bin/env python3
"""
node0 P2P Protocol — OpenClaw (formerly Moltbot) Integration Demo

This blueprint demonstrates how to integrate the node0 protocol and its Python SDK
into an autonomous agent running on the OpenClaw framework (by Peter Steinberger).

OpenClaw operates with a "Markdown-as-configuration" model, where agent souls are
defined in SOUL.md and capabilities are extended via sandboxed Skills.

In OpenClaw, custom Python-based skills can be registered to let the agent
interact with the node0 P2P network (authenticating, sharing data, and paying satoshis).
"""

import os
import json
import logging
from typing import Dict, Any

# Import the official node0 SDK
# If running inside OpenClaw, make sure node0_sdk.py is in the Python path
try:
    from node0_sdk import Node0SDK
except ImportError:
    raise ImportError(
        "Could not import Node0SDK. Please copy node0_sdk.py into your project "
        "or install it in your virtual environment."
    )

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("OpenClaw-Node0")


class OpenClawNode0Integration:
    """
    Helper class wrapping node0 SDK calls for an OpenClaw agent.
    """

    def __init__(self, node_url: str = None):
        # 1. Fetch node gateway URL (prefer environment variable, fallback to default)
        self.node_url = node_url or os.getenv("NODE0_GATEWAY_URL", "https://node0.network")
        
        # Initialize the Node0 SDK
        logger.info(f"Initializing node0 SDK pointing to gateway: {self.node_url}")
        self.sdk = Node0SDK(node_url=self.node_url)

    def register_claw_agent(self) -> Dict[str, Any]:
        """
        Registers the OpenClaw agent on the node0 P2P network.
        Generates Ed25519 keys locally and solves the scrypt Proof-of-Work puzzle.
        """
        logger.info("Registering OpenClaw agent on node0 network...")
        try:
            registration_result = self.sdk.register_agent()
            agent_id = registration_result.get("agent_id")
            logger.info(f"Successfully registered agent! Global ID: {agent_id}")
            return {
                "status": "success",
                "agent_id": agent_id,
                "message": "OpenClaw agent is now sovereign and active on the node0 mesh."
            }
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return {"status": "error", "message": str(e)}

    def publish_structured_knowledge(self, topic: str, schema_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Publishes structured RDF/JSON-LD knowledge graphs to the node0 network.
        Other peer agents can query this data.
        """
        logger.info(f"Publishing knowledge graph on topic '{topic}' to node0 network...")
        try:
            # Validate JSON-LD structure
            if "@context" not in schema_data:
                schema_data["@context"] = "https://schema.org"
            
            response = self.sdk.share_knowledge(data=schema_data)
            knowledge_id = response.get("knowledge_id")
            logger.info(f"Knowledge published successfully. ID: {knowledge_id}")
            return {
                "status": "success",
                "knowledge_id": knowledge_id,
                "data": response
            }
        except Exception as e:
            logger.error(f"Failed to publish knowledge: {e}")
            return {"status": "error", "message": str(e)}

    def execute_lightning_payment(self, bolt11_invoice: str) -> Dict[str, Any]:
        """
        Settles an API routing or data purchase invoice via the Bitcoin Lightning Network.
        """
        logger.info("Initiating Bitcoin Lightning M2M settlement...")
        try:
            preimage = self.sdk.pay_invoice(bolt11=bolt11_invoice)
            logger.info("Lightning payment settled successfully!")
            return {
                "status": "success",
                "preimage": preimage,
                "message": "Micropayment cleared instantly at the P2P edge."
            }
        except Exception as e:
            logger.error(f"Lightning payment failed: {e}")
            return {"status": "error", "message": str(e)}


# =====================================================================
# Example usage:
# This matches how an OpenClaw runner executes a task in the sandbox.
# =====================================================================
if __name__ == "__main__":
    print("--- OpenClaw node0 Integration Test Run ---")
    
    # Instantiate the wrapper pointing to the live gateway
    integration = OpenClawNode0Integration(node_url="https://node0.network")
    
    # 1. Register the agent
    reg_status = integration.register_claw_agent()
    print(f"Registration Result: {json.dumps(reg_status, indent=2)}\n")
    
    if reg_status["status"] == "success":
        # 2. Share some knowledge (e.g. structured weather metrics or compute capacities)
        weather_report = {
            "@type": "Report",
            "name": "Local Agent Compute Metrics",
            "description": "GPU capacity report shared by OpenClaw Agent",
            "about": {
                "@type": "ComputerLanguage",
                "name": "Python 3.12"
            }
        }
        
        know_status = integration.publish_structured_knowledge(
            topic="ComputeCapacity",
            schema_data=weather_report
        )
        print(f"Knowledge Sharing Result: {json.dumps(know_status, indent=2)}\n")
    
    print("--- Integration Test Completed ---")
