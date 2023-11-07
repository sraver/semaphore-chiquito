# Semaphore on Chiquito

This is a port of the [Semaphore](https://github.com/semaphore-protocol/semaphore) circuit, originally built in Circom,
to [Chiquito](https://github.com/privacy-scaling-explorations/chiquito).

## Structure

The following is a diagram of how the circuits are structured and combined in order to obtain the result.

![circuit diagram](https://github.com/semaphore-protocol/semaphore/raw/94259e1865816c61727a8d3af3d9f20689a04e16/packages/circuits/scheme.png)

## Circuits

The following circuits are added:

- **mimc7_multi**: Allows computing and verifying the hashes of a variable number of inputs, and maps the results into a lookup table.
- **inclusion_proof**: Verifies the correct computation of the last hash of the sequence.
- **semaphore**: Verifies the computed hashes used the correct input data.  











