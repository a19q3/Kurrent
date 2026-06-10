# Kurrent Factory Mode

Kurrent factory mode is represented by `FactoryState`, `VirtualChannelState`, `TouchedLeaves`, and `MaterialisationPlan`.

The local model supports:

- one compact factory state;
- multiple virtual channels;
- local materialisation of one touched virtual channel;
- duplicate materialisation rejection;
- wrong factory id rejection;
- wrong virtual channel id rejection;
- fee/principal input separation;
- conservation checks;
- rejection if untouched virtual-channel state changes.

Reduced-signature non-interference is not claimed. Until a live Kaspa script path proves a smaller authorisation rule, the safe rule is full factory authorisation for factory state transitions.
