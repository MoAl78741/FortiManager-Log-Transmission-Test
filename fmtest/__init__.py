"""FortiManager log transmission troubleshooting and correlation tool.

The tool answers one question about an intermittent fault:

    FortiManager says it generated a test event. Did that event actually leave
    the box on the wire, and did Graylog subsequently receive it?

Evidence is collected independently from four logical sources -- CLI, DEBUG,
SNIFFER and GRAYLOG -- and correlated per individual test execution.

All four phases are implemented: config and SSH, repeating command groups and
test event IDs, CLI generation detection, the concurrent packet sniffer with
payload reassembly, the optional logd debug session, Graylog polling over the
Views/Search API, and a correlation engine that matches evidence per individual
test execution -- by identity key where the evidence carries one, and by
consumable order inside a time window where it does not. Plus debug mode, the
live split-screen display, tee logging and the reports.
"""

__version__ = "1.0.0"
PHASE = 4
