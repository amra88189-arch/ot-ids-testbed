# Why CUSUM, and why a static band misses a small sustained bias
A static value band only fires when a signal leaves its frozen range. A stealthy
attacker can hold a process variable a few units off-normal but still INSIDE that
band -- e.g. pressure held at 2704 kPa, above the 2698 mean yet below where the band
fires (~2709). The band is blind to it. CUSUM accumulates the signed deviation from
the frozen mean, so a small sustained offset adds up and trips a threshold the band
never would. Demonstrated on the live plant: a +6 kPa in-band hold produced band 0,
CUSUM 58. CUSUM is edge-triggered (resets on fire) and is disabled on the integrating
tank level, whose within-band wander is normal.
