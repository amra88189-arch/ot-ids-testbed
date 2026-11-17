# Why a frozen envelope, not a rate-of-change feature
A slow sustained excursion has almost no rate of change, so phys_delta ranks it
below normal noise (AUC 0.31). A frozen, device-nature-aware operating envelope
catches the drift the derivative misses: AUC 0.97, firing in 139 s, 94% of the
event flagged. Steady signals use a value band; cycling valves use
variance-collapse plus out-of-range.
