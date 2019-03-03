use std::collections::{HashSet};
use super::utils::*;
use  super::proposer_tree::PropNode;

#[derive(Clone)]
pub struct VoterNode<'a>{
    /// The chain of the voter node
    chain_id: u16,
    /// Block Id
    node_id : BlockId,
    /// The parent on its chain
    parent: Option<&'a VoterNode<'a>>,
    /// The parent on proposer tree. This will be used for adaptive difficulty.
    proposer_parent: Option<&'a PropNode<'a>>,
    /// Height from the genesis node
    level: u32,
    /// List of votes on proposer nodes.
    votes: Vec<&'a PropNode<'a>>
}

impl<'a> VoterNode<'a>{
    pub fn set_chain_id(&mut self, chain_id: u16) {self.chain_id = chain_id}

    pub fn genesis(chain_id: u16) -> Self{
        let mut genesis = VoterNode::default();
        genesis.set_chain_id(chain_id);
        return genesis;
    }
}

impl<'a> Default for VoterNode<'a> {
    fn default() -> Self {
        let chain_id :u16 = 0;
        let node_id = BlockId::default();
        let parent: Option<&'a VoterNode<'a>> = None;
        let proposer_parent: Option<&'a PropNode<'a>> = None;
        let level = 0;
        let votes: Vec<&'a PropNode<'a>> = vec![];
        return VoterNode {chain_id, node_id, parent, proposer_parent, level, votes,};
    }
}

impl<'a> PartialEq for VoterNode<'a> {
    fn eq(&self, other: &VoterNode) -> bool {
        self.node_id == other.node_id
    }
}

impl<'a> Node for VoterNode<'a>{
    fn get_type() -> NodeType{ return NodeType::Voter }
}


/// Stores all the voter nodes
pub struct VoterChain<'a>{
    /// Voter chain id
    chain_id: u16,
    /// Genesis node
    genesis_node: Option<&'a VoterNode<'a>>,
    /// Best node on the main chain
    best_node: Option<&'a VoterNode<'a>>,
    /// Set of all Voter nodes
    voter_nodes: Vec<&'a VoterNode<'a>> //todo: Do we want to move the nodes into this ?
}

impl<'a>  Default for VoterChain<'a> {
    fn default() -> Self {
        let voter_nodes: Vec<&'a VoterNode> = vec![];
        return VoterChain {chain_id: 0, genesis_node: None, best_node: None, voter_nodes};
    }
}

impl<'a> VoterChain<'a>{
    pub fn new(genesis_node: &'a VoterNode<'a>) -> Self {
        let mut  default_chain: VoterChain<'a> = VoterChain::default();
        default_chain.set_genesis_node(genesis_node);
        return default_chain;
    }

    /// Get the best node
    pub fn get_best_node(&self) -> Option<&'a VoterNode<'a>> {
        return self.best_node;
    }

    /// Get the level of the best node
    pub fn get_chain_length(&self) -> u32 {
        return self.best_node.unwrap().level;
    }

    /// Add  voter node
    pub fn add_node(&mut self, node: &'a VoterNode<'a>){
        self.voter_nodes.push(node); //Todo: Define a hash insert??

        if node.parent == self.best_node{
            self.best_node = Some(node);
        }
        else if node.level > self.best_node.unwrap().level +1 {
            //  Todo: Reorg!! Return Success enum status?
        }
    }

    pub fn set_chain_id(&mut self, chain_id: u16){
        self.chain_id = chain_id;
    }

    pub fn set_genesis_node(&mut self, node: &'a VoterNode<'a>){
        self.genesis_node = Some(node);
        self.set_best_node(node);
    }

    pub fn set_best_node(&mut self, node: &'a VoterNode<'a>){
        self.best_node = Some(node);
    }

}