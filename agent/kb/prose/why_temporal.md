# Why temporal evaluation, not random cross-validation
Random cross-validation shuffles time and leaks near-duplicate rows across folds,
flattering a single recording. A supervised detector catches attack types it has
seen and misses novel ones: injection recall falls from 0.76 under random CV to
0.00 under a temporal (train-past, test-future) split.
