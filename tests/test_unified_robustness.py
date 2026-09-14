"""Wallet signing must reject foreign sighashes without taking the node down."""
from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK
from psbt_patch import set_input0_sighash
import pytest

pytestmark = pytest.mark.skipif(TEST_NETWORK != 'regtest', reason='Blake2b regtest only')


# SIGHASH_ALL is what every existing PSBT tool writes; the rest are legal too.
@pytest.mark.parametrize("sighash", [0x01, 0x02, 0x03, 0x81, 0x83, 0x21 | 0x80])
def test_signpsbt_foreign_sighash_is_rejected_not_fatal(node_factory, bitcoind, sighash):
    l1 = node_factory.get_node(broken_log='.*')
    a = l1.rpc.newaddr()
    bitcoind.rpc.sendtoaddress(a.get('bech32') or list(a.values())[0], 0.01)
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('Owning output')

    funded = l1.rpc.fundpsbt(satoshi=100000, feerate='253perkw', startweight=250)
    tampered = set_input0_sighash(funded['psbt'], sighash)

    with pytest.raises(Exception):
        l1.rpc.signpsbt(tampered)

    # The node must still be answering RPC, and still able to sign normally.
    assert l1.rpc.getinfo()['id'] is not None
    ok = l1.rpc.signpsbt(funded['psbt'])
    assert ok['signed_psbt'] != funded['psbt']
