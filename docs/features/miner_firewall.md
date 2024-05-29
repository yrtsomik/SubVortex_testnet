Everyday miners can be subject to different attacks such DoS (Denial of Service), DDoS (Distributed Denial of Service), etc.
To protect the miners, the miners' owners can enable the firewall feature that all miner have available.

To activate the firewall in the miner, you have add the argument `--firewall.on` in the start command

```bash
pm2 start neurons/miner.py \
  --name MINER_NAME \
  --interpreter python3 -- \
  --netuid 7 \
  --subtensor.network local \
  --wallet.name miner \
  --wallet.hotkey miner-7 \
  --logging.debug \
  --auto-update \
  --firewall.on
```

By the default, any traffic coming in will be blocked. To allow some traffic, you have to use the different options available

- `--firewall.interface` - network interface to listen traffic to, the default one is `eth0`
- `--firewall.ports` - list of port to listen the traffic to and such axon port, subtensor ports, etc
- `--firewall.ports_to_forward` - list of ports to let traffic coming in
- `--firewall.config` - path of the firewall configuration file, by default `firewall.json`

The configuration file, is a json file containing a list of ports as key with a list of options as value.

```json
[
  {
    "8091": {
      "ddos_time_window": 30,
      "ddos_packet_threshold": 100,
      "rate_limit_time_window": 5,
      "rate_limit_packet_threshold": 20
    }
  }
]
```

In this example, we are listening to all the traffic on the port 8091 and try to detect some DoS and DDoS attacks.

The firewall can detect
- DoS (Denial of Service) - it involves multiple compromised devices (often part of a botnet) sending a massive number of requests to the target server simultaneously. The distributed nature of the attack makes it more difficult to mitigate because it originates from many different sources.
- DDoS (Distributed Denial of Service) - it aims to make a machine or network resource unavailable to its intended users by overwhelming the system with a flood of illegitimate requests, thereby exhausting the server's resources (CPU, memory, bandwidth) and causing it to slow down or crash.

Recommendations
It is recommended to enable the firewall for your axon port to protected the miner accordingly. 
It is optional and as your own monitoring, you can enable the firewall for the subtensor ports such as 9944, 9933 and 30333