# Forta Agent: ETH Transfer with ERC20 Token

## Description

This Forta Agent monitors Ethereum transactions for swaps involving ERC20 tokens and detects if the transaction includes ETH transfers. It generates an alert if such a transaction is found, including the sender address, ERC20 token address, amount of ETH received by the sender, amount of ETH received as a fee by the fee collector address, and the fee percentage

## Supported Chains

- Ethereum


## Alerts


-FORTA-4: A high severity alert is generated when a transaction involving both ETH transfers and ERC20 tokens is detected. The alert includes information about the sender, ERC20 token address, fee collector address, ETH amounts received, and fee percentage.

## Test Data

The agent behaviour can be verified with the following transactions:

-  0xec7603d49bd2ede5c2bfb0e66717798a6c7adfaed730e8d143de5da390732d2a 

``` 1 findings for transaction 0xec7603d49bd2ede5c2bfb0e66717798a6c7adfaed730e8d143de5da390732d2a {
  "name": "ETH Transfer with ERC20 Token",
  "description": "Sender 0xf9f657910a74a8c0f2034641156ab668b4c5a01a swapped 0xe6545ae93a57186faddb725bee23390887302c6d ERC20 Token for 0.09850010036400776 ETH, and 0x9e2fbed0e7fc4e86f2647d9835cc966c63b607c3 received as FEE 0.17679855008217335 ETH. The FEE  is 64.22063813085643%.",
  "alertId": "FORTA-4",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Info",
  "metadata": {
    "sender": "0xf9f657910a74a8c0f2034641156ab668b4c5a01a",
    "erc20_token_address": "0xe6545ae93a57186faddb725bee23390887302c6d",
    "fee_collecter_address": "0x9e2fbed0e7fc4e86f2647d9835cc966c63b607c3",
    "sender_eth_received": "0.09850010036400776",
    "fee_collecter_address_eth_received": "0.17679855008217335",
    "FEE": "64.22063813085643"
  },
  "addresses": [],
  "labels": []
}```