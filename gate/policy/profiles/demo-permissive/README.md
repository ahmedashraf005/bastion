# Demo-permissive Gate profile

This profile is deliberately weakened solely to demonstrate Bastion's
detect → propose → harden loop. It must never protect real traffic.

It preserves the ordinary Gate policy rules but disables marker normalization
for the SampleBank configuration-marker detector. A separator- or
Unicode-whitespace-interleaved marker can therefore evade the output-stage
leak detector. The default Gate configuration remains the only profile for
normal use.
