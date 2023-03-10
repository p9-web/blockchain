import Blockchain from "@/models/chain";
import TransactionPool from "@/models/transaction-pool";
import Transaction from "@/models/transaction"
import Wallet from "@/models/wallet";
import P2pServer from "@/models/p2p-server";
import Block from "@/models/block";

export default class Miner {
    blockchain: Blockchain;
    tp: TransactionPool;
    wallet: Wallet;
    p2pServer: P2pServer;

    constructor(blockchain: Blockchain, tp: TransactionPool, wallet: Wallet, p2pServer: P2pServer) {
        this.blockchain = blockchain;
        this.tp = tp;
        this.wallet = wallet;
        this.p2pServer = p2pServer;
    }

    /**
     * Mines a new transaction on the blockchain by:
     * - Validating transactions on the transaction pool
     * - Rewarding the miner
     * - Creating new block on the blockchain consisting of the newly validated transactions
     * - Synchronizes blockchains between all other peers
     * - Clears transaction pool
     * - Broadcasts to every miner to clear their transaction pool
     */
    mine(): Block {
        const validTransactions: Transaction [] = this.tp.validTransactions();
        validTransactions.push(Transaction.newRewardTransaction(this.wallet, Wallet.getBlockchainWallet()));
        let block: Block = this.blockchain.addBlock(validTransactions);
        this.p2pServer.syncChains();
        this.tp.clear();
        this.p2pServer.broadcastClearTxs();
        return block;
    }
}
