import unittest
from unittest.mock import MagicMock
from forta_agent import Finding, FindingSeverity, FindingType
from agent import detect_eth_transfers_with_erc20

class TestDetectEthTransfersWithERC20(unittest.TestCase):

    def test_detect_eth_transfers_with_erc20(self):
        # Create a mock transaction_event object
        transaction_event = MagicMock()

        # Set up traces for the mock transaction_event
        transaction_event.traces = [
            # ERC20 transfer
            {
                "type": "call",
                "action": {
                    "call_type": "call",
                    "input": "0xa9059cbb",  # transfer(address,uint256) signature
                    "to": "0x1234567890123456789012345678901234567890",
                },
                "trace_address": [],
            },
            # Sender address trace
            {
                "type": "call",
                "action": {
                    "call_type": "call",
                    "from_": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
                },
                "trace_address": [],
            },
            # Fee collector address trace
            {
                "type": "call",
                "action": {
                    "call_type": "call",
                    "from_": "0x1234567890123456789012345678901234567890",
                    "to": "0xfedcfedcfedcfedcfedcfedcfedcfedcfedcfedc",
                    "value": 50000000000000000,  # 0.05 ETH
                },
            },
            # Sender ETH received trace
            {
                "type": "call",
                "action": {
                    "call_type": "call",
                    "to": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
                    "value": 950000000000000000,  # 0.95 ETH
                },
            },
        ]

        expected_finding = Finding(
            {
                "name": "ETH Transfer with ERC20 Token",
                "description": "Sender 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef swapped 0x1234567890123456789012345678901234567890 ERC20 Token for 0.95 ETH, and 0xfedcfedcfedcfedcfedcfedcfedcfedcfedcfedc received as FEE 0.05 ETH. The FEE  is 5.0%.",
                "alert_id": "FORTA-4",
                "severity": FindingSeverity.High,
                "type": FindingType.Info,
                "metadata": {
                    "sender": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
                    "erc20_token_address": "0x1234567890123456789012345678901234567890",
                    "fee_collecter_address": "0xfedcfedcfedcfedcfedcfedcfedcfedcfedcfedc",
                    "sender_eth_received": "0.95",
                    "fee_collecter_address_eth_received": "0.05",
                    "FEE": "5.0",
                },
            }
        )

        findings = detect_eth_transfers_with_erc20(transaction_event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0], expected_finding)


if __name__ == "__main__":
    unittest.main()
