from proxy.security.crypto_chain import compute_merkle_root

def test_merkle_root_computation():
    hashes = ["a" * 64, "b" * 64, "c" * 64]
    root = compute_merkle_root(hashes)
    assert isinstance(root, str)
    assert len(root) == 64