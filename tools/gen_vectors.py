"""Print Merkle vectors for contracts/test/unit/MerkleCompat.t.sol.
Run:  python3 tools/gen_vectors.py
The Solidity test hardcodes these values; if you change the leaf/parent format,
regenerate and update both sides.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from services.common import merkle

ADDRS = [f"0x{n*20}" for n in ("11", "22", "33", "44", "55")]
for k in (3, 5):
    t = merkle.MerkleTree(ADDRS[:k])
    print(f"// tree of first {k}: root = 0x{t.root.hex()}")
    for a in ADDRS[:k]:
        print(f"//   {a}: " + ", ".join("0x" + p.hex() for p in t.proof(a)))
