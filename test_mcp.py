import unittest
import os
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Import the tool functions directly
from node0_mcp_explore import node0_verify, node0_explain
from node0_mcp_agent import node0_identity, node0_sign, KEYS_FILE

class TestMCPTools(unittest.TestCase):

    def setUp(self):
        # Clean up keys file if it exists to start fresh
        if os.path.exists(KEYS_FILE):
            os.remove(KEYS_FILE)

    def tearDown(self):
        # Clean up keys file after tests
        if os.path.exists(KEYS_FILE):
            os.remove(KEYS_FILE)

    def test_explain(self):
        explanation = node0_explain()
        self.assertIn("node0 protocol description", explanation)
        self.assertIn("Ed25519", explanation)
        self.assertIn("Bitcoin Lightning", explanation)

    def test_identity_generation(self):
        # Generate new identity
        identity = node0_identity(action="generate")
        self.assertIn("agent_id", identity)
        self.assertIn("public_key_hex", identity)
        self.assertEqual(identity["tier"], "Ephemeral (Tier 1)")
        
        # Verify keys file was created
        self.assertTrue(os.path.exists(KEYS_FILE))
        with open(KEYS_FILE, "r") as f:
            data = json.load(f)
            self.assertEqual(data["public_key"], identity["public_key_hex"])

    def test_signing_and_verification(self):
        # Generate keys
        identity = node0_identity(action="show")
        pubkey_hex = identity["public_key_hex"]
        
        # Sign message
        message = "Test sovereign machine payment claim 123"
        sign_result = node0_sign(message)
        self.assertEqual(sign_result["message"], message)
        self.assertEqual(sign_result["public_key_hex"], pubkey_hex)
        self.assertTrue(len(sign_result["signature_hex"]) > 0)
        
        # Verify signature locally using explore verification tool
        verify_result = node0_verify(
            message=message,
            signature_hex=sign_result["signature_hex"],
            public_key_hex=pubkey_hex
        )
        self.assertTrue(verify_result["valid"])
        
        # Verify invalid signature fails
        verify_invalid = node0_verify(
            message="Modified message text",
            signature_hex=sign_result["signature_hex"],
            public_key_hex=pubkey_hex
        )
        self.assertFalse(verify_invalid["valid"])

if __name__ == "__main__":
    unittest.main()
