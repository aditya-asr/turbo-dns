# Turbo DNS

### Prerequisites

* Docker
* tmux

### Running the experiment

In terminal, `cd` into the project directory and then do:

  ```sh
  ./run_scenarios.bash
  ```

This will:

1. Build & create docker containers: `client`, `resolver`, `root nameserver`, `example nameserver`
2. Set network conditions: `100 Mbps bandwidth, 10 ms latency`
4. Sign zones with `FALCON-512`
5. Install Turbo DNS daemon on `resolver` and `example nameserver`
6. Perform 10 DNSSEC `QTYPE A` queries using `client` and report the average resolution time

 Final DNS responses of `resolver` to `client` can be found in `build/dig_logs`

### Container logs
By default, each container prints detailed logs at the expense of slight overhead.
Logging can be disabled by editing `daemon/include/constants.h`

### Changing parameters

This can be done by editing `run_scenarios.bash`


### Changing latency and bandwidth

This can be done by editing `set_network_conditions.bash`

### Errors?

* Try re-running the experiment
* For slower machines, try increasing sleep times in `tmux-run-docker-part1.bash` and `tmux-run-docker-part2.bash`