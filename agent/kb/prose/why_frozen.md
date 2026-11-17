# Why freeze the baseline instead of fitting on the batch
A baseline fit on the incoming batch inverts when attacks dominate — it becomes
the attack, ranking attacks as more normal than normal (AUC 0.154). Freezing it
on clean normal restores separation (AUC 0.973). A frozen baseline cannot be
dragged out from under a slow attack.
