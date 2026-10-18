# Research Gap and Motivation

## Motivation

Rate limiting and WAF inspection are complementary controls, but they have
different processing costs and produce different decisions. Their execution
order may influence how requests are processed, which requests reach each
security stage, and the resulting logs and measurements.

## Research Gap

A basic implementation of both controls does not, by itself, establish which
pipeline order is preferable. A meaningful comparison requires both orders
to be tested using equivalent traffic, consistent configuration, repeatable
runs, and clearly defined metrics.

The project addresses this practical evaluation need by providing a
configurable server pipeline and recording request outcomes and timing
statistics.

## Research Questions

1. Do both pipeline orders correctly handle normal and malicious requests?
2. How do the orders differ in WAF blocks and rate-limit rejections under
   mixed and high-rate traffic?
3. What differences, if any, appear in latency, throughput, and legitimate
   request success?
4. How do traffic conditions and network impairments affect the observations?

## Evaluation Approach

- Run both configurations with the same workload definitions.
- Include benign, malicious, high-rate, and mixed traffic.
- Record pipeline configuration, response status, security decisions,
  latency, throughput, and errors.
- Repeat experiments and retain raw CSV data and analysis scripts.
- Use GNS3 and Wireshark evidence where those experiments are completed.
- Report limitations and avoid generalizing from insufficient samples.

## Evidence and Limitations

Basic localhost tests confirm functional behavior but are not sufficient to
establish comparative performance under load. GNS3 topology runs, packet
captures, network-impairment tests, and CPU/memory measurements should only
be reported as completed when corresponding evidence has been collected.

Conclusions should be based on the actual recorded results, not assumed
outcomes or planned experiments.
