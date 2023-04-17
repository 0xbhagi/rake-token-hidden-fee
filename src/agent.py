import forta_agent
from forta_agent import Finding, FindingType, FindingSeverity, EntityType
from web3 import Web3


def handle_transaction(transaction_event):
    findings = []

    # Check for ETH transfers involving ERC20 tokens
    eth_transfer_findings = detect_eth_transfers_with_erc20(transaction_event)
    findings.extend(eth_transfer_findings)

    # Reduce findings to 10 because we cannot return more than 10 findings per request
    return findings[:10]


def detect_eth_transfers_with_erc20(transaction_event):
    erc20_token_address = None
    sender_address = None
    fee_collecter_address = None
    sender_eth_received = 0
    fee_collecter_address_eth_received = 0
    WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"

    transfer_sig = Web3.keccak(text="transfer(address,uint256)").hex()[0:10]
    transfer_from_sig = Web3.keccak(text="transferFrom(address,address,uint256)").hex()[0:10]

    for trace in transaction_event.traces:
        if (
            trace.type == "call"
            and trace.action.call_type == "call"
            and (trace.action.input.startswith(transfer_sig) or trace.action.input.startswith(transfer_from_sig))
            and trace.action.to != WETH
        ):
            erc20_token_address = trace.action.to

        if (
            trace.type == "call"
            and trace.action.call_type == "call"
            and not trace.trace_address
        ):
            sender_address = trace.action.from_

        if erc20_token_address and sender_address:
            if (
                trace.type == "call"
                and trace.action.call_type == "call"
                and trace.action.from_ == erc20_token_address
            ):
                fee_collecter_address = trace.action.to
                fee_collecter_address_eth_received = trace.action.value / 1e18

        if (
            trace.type == "call"
            and trace.action.call_type == "call"
            and trace.action.to == sender_address
        ):
            sender_eth_received = trace.action.value / 1e18

    if (
        erc20_token_address
        and sender_address
        and fee_collecter_address
        and sender_eth_received
        and fee_collecter_address_eth_received
    ):
        ratio = fee_collecter_address_eth_received /(sender_eth_received+fee_collecter_address_eth_received)*100
        return [
            Finding(
                {
                    "name": "ETH Transfer with ERC20 Token",
                    "description": f"Sender {sender_address} swapped {erc20_token_address} ERC20 Token for {sender_eth_received} ETH, and {fee_collecter_address} received as FEE {fee_collecter_address_eth_received} ETH. The FEE  is {ratio}%.",
                    "alert_id": "FORTA-4",
                    "severity": FindingSeverity.High,
                    "type": FindingType.Info,
                    "metadata": {
                        "sender": sender_address,
                        "erc20_token_address": erc20_token_address,
                        "fee_collecter_address": fee_collecter_address,
                        "sender_eth_received": str(sender_eth_received),
                        "fee_collecter_address_eth_received": str(fee_collecter_address_eth_received),
                        "FEE": str(ratio),
                    },
                }
            )
        ]
    return []
