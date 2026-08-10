from agent_security_lab.observability.dataflow import DataFlowTracker


def test_taint_propagation():
    df = DataFlowTracker()
    secret = "API_KEY=sk-lab-fake-key-do-not-use-in-production\nSECRET_TOKEN=x"
    df.record_output("sess", "c1", "malicious", secret, sensitive=True)
    edges = df.check_outbound("sess", "c2", "benign", "hello\n" + secret)
    assert edges
    assert edges[0].kind == "sensitive_to_outbound"
